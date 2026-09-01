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
import io.gravitee.secrets.api.errors.SecretManagerException;
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
 * Mode A3 — substitutes {@code secret://gcp/<secret>[/<version>]:<key>} references in an API
 * definition at <em>deploy</em> time, so fields no expression language can reach can still carry a
 * secret. Opt-in via {@link #DEPLOY_TIME_ENABLED_PROPERTY}, off by default.
 *
 * <h2>Why deploy time, when mode A2 exists</h2>
 *
 * A request-time reference only resolves in a field the policy hands to
 * {@code TemplateEngine.eval()} — the sole entry point that can await a deferred value. Several
 * upstream policies never do: {@code policy-generate-jwt} passes its HMAC {@code content} straight
 * to {@code new MACSigner(...)}, {@code policy-request-validation} maps ENUM constraint parameters
 * through {@code templateEngine::convert}, {@code dynamic-routing} reads its rule url with
 * {@code getValue}, and {@code policy-assign-content}'s body is FreeMarker rather than EL. For those
 * fields no request-time reference can ever work.
 *
 * <p>Substitution rewrites the step's whole raw configuration JSON before the policy deserialises
 * it, so eligibility stops being a per-field question: whatever the policy does with the value
 * afterwards, it sees a plain string.
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
 * the <em>cached</em> api object without re-registering. So the retained setters are the only way
 * the new value can get in: re-resolve, write through, then publish VALUE_CHANGED. Measured against
 * a real gateway: the API is updated in place, with no restart and no re-registration.
 *
 * <p>{@code ApiManagerImpl} acts on VALUE_CHANGED only for the {@code api-v4} and
 * {@code native-api-v4} definition kinds, so in-place rotation is confined to those. A reference in
 * any other kind of definition is still substituted at deploy time, but a later value change reaches
 * it only when that definition is itself redeployed.
 *
 * <h2>Cost</h2>
 *
 * The substituted value lives in the definition object the gateway holds, which
 * {@code ApiManagementEndpoint} serialises verbatim at {@code /_node/apis/<id>} — measured, not
 * assumed. Keep that endpoint authenticated (the shipped {@code gravitee.yml} already binds it to
 * {@code localhost} with basic auth) and keep request-time EL as the primary mechanism; this is for
 * the fields it cannot reach.
 */
public class GcpDeployTimeSecretRefs
    implements PluginHandler, EnvironmentAware, ApplicationContextAware, BeanPostProcessor, DisposableBean {

    /** Opt-in. Off by default: it trades away the {@code /_node/apis} exposure noted above. */
    public static final String DEPLOY_TIME_ENABLED_PROPERTY = "secrets.gcp.deployTime.enabled";

    /** How often retained references are re-resolved to notice a rotation. */
    public static final String ROTATION_CHECK_SECONDS_PROPERTY = "secrets.gcp.deployTime.rotationCheckSeconds";

    private static final long ROTATION_CHECK_SECONDS_DEFAULT = 60L;

    private static final String REFERENCE_SYNTAX = "secret://gcp/<secret>[/<version>]:<key>";

    /**
     * {@code secret://gcp/<secret>[/<version>]:<key>} — the gravitee.yml reference syntax, reused
     * rather than inventing a second one. Deliberately not the EL {@code {#secrets.get(...)}} form:
     * this runs before any expression language is involved and the two must stay distinguishable.
     */
    private static final Pattern SECRET_REF = Pattern.compile("secret://gcp/[A-Za-z0-9_./-]+(?::[A-Za-z0-9_.-]+)?");

    private static final Logger log = LoggerFactory.getLogger(GcpDeployTimeSecretRefs.class);

    private final CachingGcpSecretResolver injectedResolver;

    private Environment environment;
    private ApplicationContext applicationContext;
    private EventManager eventManager;
    private GcpResolverFactory.Resolver resolverHolder;
    private ScheduledExecutorService rotationChecker;

    /**
     * Keyed by {@link Definition}, which is {@code (kind, id)} — not by id alone, because ids are
     * only unique within a kind and the gateway publishes discovery events for several of them.
     */
    private final Map<Definition, Retained> retained = new ConcurrentHashMap<>();

    /**
     * @param definitionObject the very definition instance that was substituted, kept for identity
     *     comparison on REVOKE — see {@link #onRevoke}
     */
    private record Retained(
        Object definitionObject,
        Definition definition,
        String envId,
        String revision,
        List<Substitution> substitutions
    ) {}

    /** One reference-bearing field: how to re-resolve it, and how to write the result back. */
    private static final class Substitution {

        private final SecretRefsLocation location;
        private final String originalPayload;
        private final Consumer<String> setter;

        /** Written and read only by the rotation thread, so it needs no synchronisation. */
        private String lastSubstituted;

        Substitution(SecretRefsLocation location, String originalPayload, Consumer<String> setter, String lastSubstituted) {
            this.location = location;
            this.originalPayload = originalPayload;
            this.setter = setter;
            this.lastSubstituted = lastSubstituted;
        }
    }

    public GcpDeployTimeSecretRefs() {
        this(null);
    }

    /** Test seam: a resolver over a stub Secret Manager client, so no Vert.x needs to be created. */
    GcpDeployTimeSecretRefs(CachingGcpSecretResolver injectedResolver) {
        this.injectedResolver = injectedResolver;
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

        long checkSeconds = environment.getProperty(ROTATION_CHECK_SECONDS_PROPERTY, Long.class, ROTATION_CHECK_SECONDS_DEFAULT);
        rotationChecker = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "gcp-deploytime-rotation");
            thread.setDaemon(true);
            return thread;
        });
        rotationChecker.scheduleWithFixedDelay(this::checkForRotations, checkSeconds, checkSeconds, TimeUnit.SECONDS);

        log.info(
            "GCP deploy-time secret substitution ACTIVE: '{}' references in API definitions are replaced at deploy time, " +
                "rotation checked every {}s. The substituted value is readable at /_node/apis/<id> — keep that endpoint authenticated.",
            REFERENCE_SYNTAX,
            checkSeconds
        );
        return bean;
    }

    // ── Deploy ────────────────────────────────────────────────────────────────

    private void onDiscover(SecretDiscoveryEvent event) {
        Object definitionObject = event.definition();
        DefinitionSecretRefsFinder<Object> finder = finderFor(definitionObject);
        if (finder == null) {
            return;
        }
        DefinitionDescriptor descriptor = finder.toDefinitionDescriptor(definitionObject, event.metadata());
        Definition definition = descriptor.definition();
        String revision = descriptor.revision().orElse(null);

        List<Substitution> found = new ArrayList<>();
        finder.findSecretRefs(definitionObject, (payload, location, setter) -> {
            if (payload == null || !SECRET_REF.matcher(payload).find()) {
                return;
            }
            String substituted = substitute(payload, location);
            setter.accept(substituted);
            found.add(new Substitution(location, payload, setter, substituted));
            log.info("Substituted a gcp reference at {}", location);
        });

        if (found.isEmpty()) {
            onDiscoverWithNothingToSubstitute(definition, definitionObject, revision);
            return;
        }
        /*
         * Replaces any entry for the same definition. A redeploy publishes DISCOVER for the new
         * revision and REVOKE for the old, in that order, so overwriting here and letting onRevoke
         * check identity is what stops the old revision's REVOKE dropping the new entry.
         */
        retained.put(definition, new Retained(definitionObject, definition, event.envId(), revision, found));
        log.info("Retained {} substitution(s) for {} revision {}", found.size(), definition, forLog(revision));
    }

    /**
     * A DISCOVER that found nothing is two different situations, and telling them apart is what keeps
     * rotation working.
     *
     * <ul>
     *   <li><b>The same definition instance already substituted.</b> Its references are gone
     *       precisely <em>because</em> they were replaced, so there is nothing left for the pattern
     *       to match. {@code ApiManagerImpl.refresh()} re-registers the cached api objects with
     *       {@code force=true}, which republishes DISCOVER for exactly those instances — dropping the
     *       entry here would silently stop rotation after any gateway tag or configuration reload.
     *   <li><b>A different instance.</b> A genuinely new revision that no longer references a secret,
     *       so whatever is retained belongs to a superseded revision and must go. A forced
     *       re-register goes through {@code deploy()}, which publishes no REVOKE at all, so this is
     *       the only place that release can happen.
     * </ul>
     */
    private void onDiscoverWithNothingToSubstitute(Definition definition, Object definitionObject, String revision) {
        retained.compute(definition, (key, current) -> {
            if (current == null) {
                return null;
            }
            if (current.definitionObject() == definitionObject) {
                log.debug(
                    "Re-discovered {} revision {}; keeping its {} retained substitution(s)",
                    definition,
                    forLog(revision),
                    current.substitutions().size()
                );
                return current;
            }
            log.info(
                "Released {} retained substitution(s) for {}: revision {} supersedes revision {} and references no gcp secret",
                current.substitutions().size(),
                definition,
                forLog(revision),
                forLog(current.revision())
            );
            return null;
        });
    }

    // ── Revoke ────────────────────────────────────────────────────────────────

    /**
     * Releases what a definition retained, but only when the REVOKE really is for the revision now in
     * force.
     *
     * <p>{@code ApiManagerImpl.update(api)} publishes DISCOVER for the new revision <em>before</em>
     * REVOKE for the previous one, so a naive handler would let the superseded revision's REVOKE drop
     * the entry the live revision depends on — rotation would then stop, silently, on the first
     * redeploy.
     *
     * <p>The test is object identity. {@code deploy()} and {@code update()} publish DISCOVER carrying
     * the api's own definition instance and {@code undeploy()} publishes REVOKE carrying that same
     * instance, whereas {@code update()}'s REVOKE carries the <em>previous</em> api's instance.
     * Identity is used rather than the revision string because the revision comes from the optional
     * {@code deployment_number} event property: a sync source that sets none would otherwise compare
     * {@code null} to {@code null} and release on every redeploy. The revision is still honoured as a
     * fallback, so an unforeseen re-parse of the live revision cannot strand an entry forever.
     */
    private void onRevoke(SecretDiscoveryEvent event) {
        Object definitionObject = event.definition();
        DefinitionSecretRefsFinder<Object> finder = finderFor(definitionObject);
        if (finder == null) {
            return;
        }
        DefinitionDescriptor descriptor = finder.toDefinitionDescriptor(definitionObject, event.metadata());
        Definition definition = descriptor.definition();
        String revoked = descriptor.revision().orElse(null);

        retained.compute(definition, (key, current) -> {
            if (current == null) {
                return null;
            }
            boolean sameInstance = current.definitionObject() == definitionObject;
            boolean sameRevision = revoked != null && Objects.equals(current.revision(), revoked);
            if (!sameInstance && !sameRevision) {
                log.debug(
                    "Ignoring REVOKE of {} revision {}; it is superseded by the retained revision {}",
                    definition,
                    forLog(revoked),
                    forLog(current.revision())
                );
                return current;
            }
            log.info(
                "Released {} retained substitution(s) for {} revision {}",
                current.substitutions().size(),
                definition,
                forLog(revoked)
            );
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
                log.warn("Rotation check failed for {}: {}", entry.definition(), e.toString());
            }
        }
    }

    private void rotate(Retained entry) {
        boolean changed = false;
        for (Substitution substitution : entry.substitutions()) {
            String resubstituted = substitute(substitution.originalPayload, substitution.location);
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
        log.info("Publishing VALUE_CHANGED for {} so it redeploys in place", entry.definition());
        eventManager.publishEvent(
            SecretDiscoveryEventType.VALUE_CHANGED,
            new SecretDiscoveryEvent(entry.envId(), entry.definition(), new DefinitionMetadata(entry.revision()))
        );
    }

    // ── Resolution ────────────────────────────────────────────────────────────

    /**
     * Replaces every reference in a raw configuration payload with its resolved value.
     *
     * <p>A resolution failure is deliberately not swallowed. On the DISCOVER path it propagates out
     * of {@code ApiManagerImpl.deploy}/{@code update} and fails that API's deployment, which is the
     * safe outcome — the alternative is an API served with a literal {@code secret://gcp/...} in a
     * credential field. On the rotation path {@link #checkForRotations()} logs it and the value
     * already in force stays.
     */
    private String substitute(String payload, SecretRefsLocation location) {
        Matcher matcher = SECRET_REF.matcher(payload);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String value = resolve(matcher.group(), location);
            // The payload is JSON and the value lands inside a JSON string literal, so a quote or
            // backslash in a secret would otherwise break out of it.
            matcher.appendReplacement(out, Matcher.quoteReplacement(escapeForJsonStringBody(value)));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    private String resolve(String reference, SecretRefsLocation location) {
        // secret://gcp/... -> /gcp/..., the URI form SecretURL.from expects.
        String uri = reference.substring("secret:/".length());
        try {
            /*
             * blockingGet is correct here and only here. Deploy-time substitution runs on an
             * API-manager or sync executor thread, or this class's own rotation thread — never a
             * Vert.x event loop — and the SPI setter it feeds is synchronous, so there is nothing to
             * defer to. Request-time resolution is the opposite case, which is why GcpSecretsElHolder
             * returns Single.
             */
            return resolver().resolveKey(SecretURL.from(uri, true)).blockingGet();
        } catch (RuntimeException e) {
            // Name the location. Without it the failure reads as a bare "secret not found" against a
            // definition whose reference could be in any of a dozen plugin configurations.
            throw new SecretManagerException(
                "Could not resolve '%s' at %s while substituting an API definition at deploy time".formatted(reference, location),
                e
            );
        }
    }

    private synchronized CachingGcpSecretResolver resolver() {
        if (injectedResolver != null) {
            return injectedResolver;
        }
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

    /** The revision is optional, and {@code null} in a log line reads as a bug rather than a fact. */
    private static String forLog(String revision) {
        return revision == null ? "(none)" : revision;
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
