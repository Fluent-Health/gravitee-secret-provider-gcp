/*
 * Copyright © 2026 Fluent Health (https://fluentinhealth.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.fluenthealth.gravitee.secretprovider.gcp.el;

import io.fluenthealth.gravitee.secretprovider.gcp.core.CachingGcpSecretResolver;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpConfig;
import io.gravitee.common.event.EventManager;
import io.gravitee.plugin.core.api.Plugin;
import io.gravitee.plugin.core.api.PluginHandler;
import io.gravitee.secrets.api.core.SecretURL;
import io.gravitee.secrets.api.discovery.Definition;
import io.gravitee.secrets.api.discovery.DefinitionDescriptor;
import io.gravitee.secrets.api.discovery.DefinitionMetadata;
import io.gravitee.secrets.api.discovery.DefinitionSecretRefsFinder;
import io.gravitee.secrets.api.discovery.SecretRefsLocation;
import io.gravitee.secrets.api.event.SecretDiscoveryEvent;
import io.gravitee.secrets.api.event.SecretDiscoveryEventType;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

/**
 * <strong>SPIKE / RFC — opt-in, default off, not a supported feature.</strong>
 *
 * <p>Substitutes {@code secret://gcp/<secret>[/<version>]:<key>} references in an API definition at
 * <em>deploy</em> time, so fields no expression language can reach can still carry a secret:
 * {@code policy-generate-jwt}'s HMAC {@code content}, {@code request-validation} ENUM constraints,
 * {@code dynamic-routing} urls, {@code policy-assign-content}'s FreeMarker body, a JWT plan's
 * {@code resolverParameter}. Substitution rewrites the raw configuration JSON before the policy
 * deserialises it, so eligibility is not a per-field decision at all.
 *
 * <h2>The seam</h2>
 *
 * {@code ApiManagerImpl.deploy(api)} publishes {@code SecretDiscoveryEventType.DISCOVER} carrying
 * {@code api.getDefinition()} immediately before {@code ReactorEvent.DEPLOY}; {@code update(api)}
 * does the same before {@code ReactorEvent.UPDATE}, then publishes {@code REVOKE} for the previous
 * revision. {@code EventManagerImpl} holds only a listeners map — no executor, queue or future
 * anywhere in the class — so dispatch is synchronous on the publishing thread and this listener
 * finishes substituting before the reactor is built. Every deploying path funnels through those two
 * methods, so there is no second hook and no core bean to wrap.
 *
 * <h2>Two shapes of the same event</h2>
 *
 * {@code SecretDiscoveryEvent.definition()} is {@code Object}, and it is <em>not</em> the same thing
 * on the way in and the way out. On DISCOVER and REVOKE the gateway passes the raw definition model
 * (a V4 {@code Api}), which is what the finders accept. On VALUE_CHANGED, {@code ApiManagerImpl}
 * pattern-matches against the {@link Definition} <em>record</em> and uses its {@code id} to look up
 * the cached api and its {@code kind} to filter. {@code finder.toDefinitionDescriptor(...)} converts
 * one to the other; skipping that conversion makes this class silently do nothing.
 *
 * <h2>Rotation</h2>
 *
 * {@code updateApiOnSecretChange} republishes no DISCOVER — it fires {@code ReactorEvent.UPDATE} for
 * the <em>cached</em> api object without re-registering. So the retained setters are the only way the
 * new value can get in: re-resolve, write through, then publish VALUE_CHANGED.
 *
 * <h2>Cost</h2>
 *
 * The substituted value lives in the definition object the gateway holds, which
 * {@code ApiManagementEndpoint} serialises verbatim at {@code /_node/apis/<id>}. Request-time EL
 * stays the primary mechanism; this is for the fields it cannot reach.
 */
public class GcpDeployTimeSecretRefs
    implements PluginHandler, EnvironmentAware, ApplicationContextAware, BeanPostProcessor, DisposableBean {

    /** Opt-in. Off by default: this is a spike, and it trades away the exposure noted above. */
    public static final String DEPLOY_TIME_ENABLED_PROPERTY = "secrets.gcp.deployTime.enabled";

    /** How often retained references are re-resolved to notice a rotation. */
    public static final String ROTATION_CHECK_SECONDS_PROPERTY = "secrets.gcp.deployTime.rotationCheckSeconds";

    /**
     * {@code secret://gcp/<secret>[/<version>]:<key>} — the gravitee.yml reference syntax, reused
     * rather than inventing a second one. Deliberately not the EL {@code {#secrets.get(...)}} form:
     * this runs before any expression language is involved and the two must stay distinguishable.
     */
    private static final Pattern SECRET_REF = Pattern.compile("secret://gcp/[A-Za-z0-9_./-]+(?::[A-Za-z0-9_.-]+)?");

    private static final Logger log = LoggerFactory.getLogger(GcpDeployTimeSecretRefs.class);

    private Environment environment;
    private ApplicationContext applicationContext;
    private EventManager eventManager;
    private GcpResolverFactory.Resolver resolverHolder;
    private ScheduledExecutorService rotationChecker;

    /** Keyed by definition id, so a rotation can rewrite what was already substituted. */
    private final Map<String, Retained> retained = new ConcurrentHashMap<>();

    private record Retained(Definition definition, String envId, String revision, List<Substitution> substitutions) {}

    private static final class Substitution {

        private final SecretRefsLocation location;
        private final String originalPayload;
        private final Consumer<String> setter;
        private String lastSubstituted;

        Substitution(SecretRefsLocation location, String originalPayload, Consumer<String> setter, String lastSubstituted) {
            this.location = location;
            this.originalPayload = originalPayload;
            this.setter = setter;
            this.lastSubstituted = lastSubstituted;
        }
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    /**
     * Arms both subscriptions the moment the {@link EventManager} bean exists.
     *
     * <p>Being a {@link BeanPostProcessor} is what guarantees this runs before any API deploys.
     * Hooking the {@code EventManager} as it is created, rather than calling {@code getBean}, avoids
     * forcing that bean into existence out of order from inside a post-processor.
     */
    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (!(bean instanceof EventManager candidate) || eventManager != null) {
            return bean;
        }
        if (!environment.getProperty(DEPLOY_TIME_ENABLED_PROPERTY, Boolean.class, false)) {
            log.debug("GCP deploy-time secret substitution INACTIVE ({}=false)", DEPLOY_TIME_ENABLED_PROPERTY);
            return bean;
        }

        this.eventManager = candidate;
        candidate.subscribeForEvents(
            event -> {
                if (event.content() instanceof SecretDiscoveryEvent discovery) {
                    onDiscover(discovery);
                }
            },
            SecretDiscoveryEventType.DISCOVER
        );
        candidate.subscribeForEvents(
            event -> {
                if (event.content() instanceof SecretDiscoveryEvent discovery) {
                    onRevoke(discovery);
                }
            },
            SecretDiscoveryEventType.REVOKE
        );

        long checkSeconds = environment.getProperty(ROTATION_CHECK_SECONDS_PROPERTY, Long.class, 60L);
        rotationChecker = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "gcp-deploytime-rotation");
            thread.setDaemon(true);
            return thread;
        });
        rotationChecker.scheduleWithFixedDelay(this::checkForRotations, checkSeconds, checkSeconds, TimeUnit.SECONDS);

        log.info("GCP deploy-time secret substitution ARMED (DISCOVER + REVOKE, rotation check every {}s)", checkSeconds);
        return bean;
    }

    // ── Deploy ────────────────────────────────────────────────────────────────

    private void onDiscover(SecretDiscoveryEvent event) {
        DefinitionSecretRefsFinder<Object> finder = finderFor(event.definition());
        if (finder == null) {
            return;
        }
        DefinitionDescriptor descriptor = finder.toDefinitionDescriptor(event.definition(), event.metadata());

        List<Substitution> found = new ArrayList<>();
        finder.findSecretRefs(event.definition(), (payload, location, setter) -> {
            if (payload == null || !SECRET_REF.matcher(payload).find()) {
                return;
            }
            String substituted = substitute(payload);
            setter.accept(substituted);
            found.add(new Substitution(location, payload, setter, substituted));
            log.info("Substituted a gcp reference at {}", location);
        });

        if (found.isEmpty()) {
            return;
        }
        Definition definition = descriptor.definition();
        /*
         * Replaces any entry for the same id. A redeploy publishes DISCOVER for the new revision and
         * REVOKE for the old, in that order, so keying by id and letting REVOKE check the revision is
         * what stops the old revision's REVOKE dropping the new entry.
         */
        retained.put(definition.id(), new Retained(definition, event.envId(), descriptor.revision().orElse(null), found));
        log.info(
            "Retained {} substitution(s) for definition {} revision {}",
            found.size(),
            definition.id(),
            descriptor.revision().orElse("-")
        );
    }

    private void onRevoke(SecretDiscoveryEvent event) {
        DefinitionSecretRefsFinder<Object> finder = finderFor(event.definition());
        if (finder == null) {
            return;
        }
        DefinitionDescriptor descriptor = finder.toDefinitionDescriptor(event.definition(), event.metadata());
        String id = descriptor.definition().id();
        String revoked = descriptor.revision().orElse(null);

        retained.compute(id, (key, current) -> {
            if (current == null) {
                return null;
            }
            if (!Objects.equals(current.revision(), revoked)) {
                // A superseded revision being revoked after the new one was already retained.
                log.debug("Ignoring REVOKE for {} revision {}; retained revision is {}", id, revoked, current.revision());
                return current;
            }
            log.info("Released {} retained substitution(s) for definition {} revision {}", current.substitutions().size(), id, revoked);
            return null;
        });
    }

    // ── Rotation ──────────────────────────────────────────────────────────────

    /**
     * Re-resolves everything retained and, where a value moved, writes it through the retained setter
     * and asks the gateway to redeploy that one API in place.
     */
    void checkForRotations() {
        for (Retained entry : retained.values()) {
            try {
                rotate(entry);
            } catch (Exception e) {
                // One bad definition must not kill the scheduler for every other one.
                log.warn("Rotation check failed for definition {}: {}", entry.definition().id(), e.toString());
            }
        }
    }

    private void rotate(Retained entry) {
        boolean changed = false;
        for (Substitution substitution : entry.substitutions()) {
            String resubstituted = substitute(substitution.originalPayload);
            if (resubstituted.equals(substitution.lastSubstituted)) {
                continue;
            }
            substitution.setter.accept(resubstituted);
            substitution.lastSubstituted = resubstituted;
            changed = true;
            log.info("Secret value changed at {}", substitution.location);
        }
        if (!changed) {
            return;
        }
        log.info("Publishing VALUE_CHANGED for definition {} so it redeploys in place", entry.definition().id());
        eventManager.publishEvent(
            SecretDiscoveryEventType.VALUE_CHANGED,
            new SecretDiscoveryEvent(entry.envId(), entry.definition(), new DefinitionMetadata(entry.revision()))
        );
    }

    // ── Resolution ────────────────────────────────────────────────────────────

    /** Replaces every reference in a raw configuration payload with its resolved value. */
    private String substitute(String payload) {
        Matcher matcher = SECRET_REF.matcher(payload);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String value = resolve(matcher.group());
            // The payload is JSON and the value lands inside a JSON string literal, so a quote or
            // backslash in a secret would otherwise break out of it.
            matcher.appendReplacement(out, Matcher.quoteReplacement(escapeForJsonStringBody(value)));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    private String resolve(String reference) {
        // secret://gcp/... -> /gcp/..., the URI form SecretURL.from expects.
        String uri = reference.substring("secret:/".length());
        /*
         * blockingGet is correct here and only here. Deploy-time substitution runs on an API-manager
         * or sync executor thread, or this class's own rotation thread — never a Vert.x event loop —
         * and the SPI setter it feeds is synchronous, so there is nothing to defer to. Request-time
         * resolution is the opposite case, which is why GcpSecretsElHolder returns Single.
         */
        return resolver().resolveKey(SecretURL.from(uri, true)).blockingGet();
    }

    private synchronized CachingGcpSecretResolver resolver() {
        if (resolverHolder == null) {
            GcpConfig config = GcpElConfigReader.read(environment);
            resolverHolder = GcpResolverFactory.create(config, "gravitee-secret-provider-gcp-deploytime");
        }
        return resolverHolder.resolver();
    }

    private static String escapeForJsonStringBody(String value) {
        StringBuilder sb = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private DefinitionSecretRefsFinder<Object> finderFor(Object definition) {
        if (definition == null) {
            return null;
        }
        return applicationContext
            .getBeansOfType(DefinitionSecretRefsFinder.class)
            .values()
            .stream()
            .filter(candidate -> candidate.canHandle(definition))
            .map(candidate -> (DefinitionSecretRefsFinder<Object>) candidate)
            .findFirst()
            .orElse(null);
    }

    @Override
    public void destroy() {
        if (rotationChecker != null) {
            rotationChecker.shutdownNow();
        }
        if (resolverHolder != null) {
            resolverHolder.close();
        }
    }

    /** Always {@code false}; {@link PluginHandler} is only how this class becomes a bean. */
    @Override
    public boolean canHandle(Plugin plugin) {
        return false;
    }

    @Override
    public void handle(Plugin plugin) {
        // Intentionally empty; see canHandle.
    }
}
