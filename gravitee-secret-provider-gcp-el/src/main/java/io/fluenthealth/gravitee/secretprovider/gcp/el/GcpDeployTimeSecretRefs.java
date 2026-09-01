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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
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
 * <h2>Which references are touched, and what happens to the rest</h2>
 *
 * Only {@code secret://gcp/...}. A reference naming another provider is left in place and logged at
 * {@code WARN}; a {@code gcp} one that cannot be parsed, resolved or encoded fails the deployment.
 * Nothing is ever left in place <em>silently</em> — a literal reference surviving into a credential
 * field is answered by the far end with a 401 that names nothing, which is the failure this design
 * exists to avoid. See {@link #substitute}.
 *
 * <h2>The {@code ?encoding=base64} modifier</h2>
 *
 * Some fields want the credential encoded rather than raw, and the requirement belongs to the
 * <em>field</em> rather than to the secret. The motivating case is a JWT plan's
 * {@code resolverParameter} with {@code publicKeyResolver: GIVEN_KEY}: the policy hands the value to
 * {@code JWKBuilder.buildHMACKey}, which tries {@code Base64.getDecoder().decode(keyValue)} first and
 * falls back to {@code keyValue.getBytes()} only when that throws. Passing a raw secret that
 * <em>happens</em> to be valid base64 therefore yields the decoded bytes as the key, silently, and
 * every token on that plan is rejected. Encoding first makes the decode branch deterministic, so the
 * key bytes are exactly the secret's bytes.
 *
 * <p>The alternative — storing a second, pre-encoded copy of the credential — works exactly once:
 * the two copies then have to be rotated together, nothing about either opaque blob reveals that
 * they have drifted, and the rotation described below would propagate whichever half was updated.
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

    /** Query parameter that transforms the resolved value before it is substituted in. */
    public static final String ENCODING_QUERY_PARAM = "encoding";

    private static final String ENCODING_BASE64 = "base64";

    /**
     * Every query parameter something in the resolution path actually reads: {@code encoding} here,
     * {@code version} in {@code GcpSecretLocation}, and {@code keymap}/{@code watch} in
     * {@code SecretURL}. Anything else is a typo or an overrun match — see
     * {@link #rejectUnknownQueryParams}.
     */
    private static final Set<String> KNOWN_QUERY_PARAMS = Set.of(ENCODING_QUERY_PARAM, "version", "keymap", "watch");

    private static final String REFERENCE_SYNTAX = "secret://gcp/<secret>[/<version>]:<key>[?encoding=base64]";

    private static final String SECRET_URL_SCHEME = "secret://";

    private static final String GCP_PROVIDER = "gcp";

    /**
     * Matches any {@code secret://<provider>/...} run, deliberately — <em>not</em> only a well-formed
     * gcp one.
     *
     * <p>A pattern that matched only valid references would leave a misspelled one
     * ({@code secret://gpc/...}, {@code ?encodng=base64}) sitting in the deployed definition as
     * literal text, to travel upstream as a credential and come back as a 401 that names nothing.
     * Matching broadly and rejecting in {@link #resolveReference} is what makes that case loud.
     *
     * <p>Broad, but not greedy — a reference may be <em>embedded</em> in a larger value, and where it
     * ends decides what happens to the text after it. Two boundaries are load-bearing, because
     * overrunning either substitutes the <em>right</em> value into the <em>wrong</em> string, which
     * nothing downstream can catch:
     *
     * <ul>
     *   <li><b>The path never ends in {@code /}.</b> {@code SecretURL} strips trailing slashes, so a
     *       trailing one can never belong to the reference — it is the separator before whatever
     *       follows, as in a {@code dynamic-routing} rule url. Hence segments joined by {@code /},
     *       rather than a character class that contains it.
     *   <li><b>{@code &} counts only after a {@code ?}.</b> It separates query parameters, so outside
     *       a query string it belongs to the surrounding text — a form-encoded
     *       {@code policy-assign-content} body, say. Hence the separate optional query group.
     * </ul>
     *
     * <p>The reference syntax is the {@code gravitee.yml} one, reused rather than invented.
     * Deliberately not the EL {@code {#secrets.get(...)}} form: this runs before any expression
     * language is involved, and the two must stay distinguishable.
     */
    private static final Pattern SECRET_REF_CANDIDATE = Pattern.compile(
        "secret://(?<provider>[A-Za-z0-9_.-]*)/(?<path>[A-Za-z0-9_.:%+-]+(?:/[A-Za-z0-9_.:%+-]+)*)?(?<query>\\?[A-Za-z0-9_.:=&%+-]*)?"
    );

    /**
     * What {@code ?encoding=} does to a resolved value before it is written into the definition.
     *
     * <p>The encoding belongs to the <em>field</em>, not to the secret, which is why it lives on the
     * reference rather than in Secret Manager. Storing a second, pre-encoded copy of a credential
     * would work exactly once: the two copies then have to be rotated together, and nothing about
     * either blob reveals that they have drifted apart. See the README for the case that motivated
     * this — a JWT plan's {@code resolverParameter}.
     */
    private enum Encoding {
        NONE {
            @Override
            String apply(String value) {
                return value;
            }
        },
        /** Explicit UTF-8, so the result cannot depend on the gateway's platform default charset. */
        BASE64 {
            @Override
            String apply(String value) {
                return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
            }
        };

        abstract String apply(String value);
    }

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
            if (payload == null || !payload.contains(SECRET_URL_SCHEME)) {
                return;
            }
            String substituted = substitute(payload, location);
            if (substituted.equals(payload)) {
                // Only references belonging to another provider, which substitute() has warned about.
                return;
            }
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
     * Replaces every {@code gcp} reference in a raw configuration payload with its resolved value.
     *
     * <p>Nothing here is swallowed, because every silent outcome is worse than a failed deployment:
     *
     * <ul>
     *   <li>A <b>malformed gcp reference</b> — a bad URL, an unknown {@code ?encoding}, a secret that
     *       cannot be read — throws. On the DISCOVER path that propagates out of
     *       {@code ApiManagerImpl.deploy}/{@code update} and fails that API's deployment. The
     *       alternative is an API served with a literal {@code secret://gcp/...} in a credential
     *       field, which the far end answers with a 401 and nobody notices.
     *   <li>A reference for <b>another provider</b> is left alone — this plugin does not own it — but
     *       logged at {@code WARN}, which survives the gateway's default {@code <root level="WARN">}
     *       where our {@code INFO} lines do not. A misspelled provider is the likely cause, and that
     *       is the one case that would otherwise stay invisible.
     * </ul>
     *
     * <p>On the rotation path {@link #checkForRotations()} catches and logs, and the value already in
     * force stays.
     */
    private String substitute(String payload, SecretRefsLocation location) {
        Matcher matcher = SECRET_REF_CANDIDATE.matcher(payload);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String reference = matcher.group();
            if (!GCP_PROVIDER.equalsIgnoreCase(matcher.group("provider"))) {
                /*
                 * Skipping the match entirely is safe: the next appendReplacement copies everything
                 * from the current append position, which includes this text verbatim.
                 */
                log.warn(
                    "Leaving '{}' at {} untouched — this plugin only substitutes '{}' references. " +
                        "If that was meant to be one, it is misspelled and is now literal text in the deployed definition.",
                    reference,
                    location,
                    SECRET_URL_SCHEME + GCP_PROVIDER + "/"
                );
                continue;
            }
            String value = resolveReference(reference, location);
            // The payload is JSON and the value lands inside a JSON string literal, so a quote or
            // backslash in a secret would otherwise break out of it.
            matcher.appendReplacement(out, Matcher.quoteReplacement(escapeForJsonStringBody(value)));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    private String resolveReference(String reference, SecretRefsLocation location) {
        // secret://gcp/... -> /gcp/..., the URI form SecretURL.from expects.
        String uri = reference.substring(SECRET_URL_SCHEME.length() - 1);
        SecretURL secretURL;
        try {
            secretURL = SecretURL.from(uri, true);
        } catch (RuntimeException e) {
            throw new SecretManagerException(
                "'%s' at %s is not a usable secret reference: %s. Expected '%s'.".formatted(
                    reference,
                    location,
                    e.getMessage(),
                    REFERENCE_SYNTAX
                ),
                e
            );
        }
        rejectUnknownQueryParams(secretURL, reference, location);
        Encoding encoding = encodingOf(secretURL, reference, location);
        try {
            /*
             * blockingGet is correct here and only here. Deploy-time substitution runs on an
             * API-manager or sync executor thread, or this class's own rotation thread — never a
             * Vert.x event loop — and the SPI setter it feeds is synchronous, so there is nothing to
             * defer to. Request-time resolution is the opposite case, which is why GcpSecretsElHolder
             * returns Single.
             */
            return encoding.apply(resolver().resolveKey(secretURL).blockingGet());
        } catch (RuntimeException e) {
            // Name the location. Without it the failure reads as a bare "secret not found" against a
            // definition whose reference could be in any of a dozen plugin configurations.
            throw new SecretManagerException(
                "Could not resolve '%s' at %s while substituting an API definition at deploy time".formatted(reference, location),
                e
            );
        }
    }

    /**
     * Rejects a query parameter nobody consumes.
     *
     * <p>{@code SecretURL} parses the query string into a multimap and silently discards what it does
     * not recognise, so without this a typo would be ignored rather than reported. It also closes a
     * subtler hole: once a reference carries a {@code ?}, a following {@code &} is a parameter
     * separator by URL grammar, so a reference with a query string embedded in a form-encoded body
     * absorbs the {@code &} and everything up to the next character that cannot appear in a query.
     * That yields an empty-named parameter here, and failing on it turns a silently mangled body into
     * a failed deployment.
     */
    private static void rejectUnknownQueryParams(SecretURL secretURL, String reference, SecretRefsLocation location) {
        for (String name : secretURL.query().keySet()) {
            if (!KNOWN_QUERY_PARAMS.contains(name)) {
                throw new SecretManagerException(
                    ("'%s' at %s carries the unrecognised query parameter '%s'. Supported: %s. " +
                        "A reference with a query string must end the value or be followed by something other than '&', " +
                        "which would otherwise be read as another parameter.").formatted(reference, location, name, KNOWN_QUERY_PARAMS)
                );
            }
        }
    }

    /**
     * Reads {@code ?encoding=} off a reference.
     *
     * <p>The query string is parsed by {@link SecretURL} itself and unknown parameters are ignored
     * there, which is what lets a modifier live in the syntax the platform already defines —
     * {@code keymap}, {@code watch} and this repo's own {@code version} are the same shape. It also
     * means an unknown parameter would be silently discarded, so the value is validated here rather
     * than left to a default.
     */
    private static Encoding encodingOf(SecretURL secretURL, String reference, SecretRefsLocation location) {
        Collection<String> requested = secretURL.query().get(ENCODING_QUERY_PARAM);
        if (requested.isEmpty()) {
            return Encoding.NONE;
        }
        if (requested.size() > 1) {
            throw new SecretManagerException(
                "'%s' at %s sets '%s' %d times; it may be set at most once".formatted(
                    reference,
                    location,
                    ENCODING_QUERY_PARAM,
                    requested.size()
                )
            );
        }
        String encoding = requested.iterator().next().trim();
        if (ENCODING_BASE64.equalsIgnoreCase(encoding)) {
            return Encoding.BASE64;
        }
        throw new SecretManagerException(
            "'%s' at %s asks for %s='%s', which is not supported. The only supported value is '%s'.".formatted(
                reference,
                location,
                ENCODING_QUERY_PARAM,
                encoding,
                ENCODING_BASE64
            )
        );
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
