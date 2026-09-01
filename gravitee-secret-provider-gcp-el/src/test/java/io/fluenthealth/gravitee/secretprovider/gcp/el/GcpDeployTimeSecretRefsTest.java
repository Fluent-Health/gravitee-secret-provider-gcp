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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.fluenthealth.gravitee.secretprovider.gcp.core.CachingGcpSecretResolver;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpConfig;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpSecretManagerClient;
import io.gravitee.common.event.impl.EventManagerImpl;
import io.gravitee.secrets.api.discovery.Definition;
import io.gravitee.secrets.api.discovery.DefinitionDescriptor;
import io.gravitee.secrets.api.discovery.DefinitionMetadata;
import io.gravitee.secrets.api.discovery.DefinitionSecretRefsFinder;
import io.gravitee.secrets.api.discovery.DefinitionSecretRefsListener;
import io.gravitee.secrets.api.discovery.SecretRefsLocation;
import io.gravitee.secrets.api.event.SecretDiscoveryEvent;
import io.gravitee.secrets.api.event.SecretDiscoveryEventType;
import io.reactivex.rxjava3.core.Maybe;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

/**
 * The deploy-time substitution lifecycle, driven through a real {@link EventManagerImpl} with the
 * same event sequences {@code ApiManagerImpl} publishes.
 *
 * <p>REVOKE is what this class exists for. {@code ApiManagerImpl.update(api)} publishes DISCOVER for
 * the new revision <em>before</em> REVOKE for the previous one, so the two ways to get it wrong are
 * both silent: drop the entry the live revision needs and rotation stops for good, or keep a
 * superseded one and a dead definition is rewritten and redeployed on every value change. Neither
 * surfaces as an error, so both are asserted here behaviourally — by whether a later rotation reaches
 * the definition the gateway is actually serving.
 *
 * <p>{@code GcpDeployTimeRevocationIT} drives the same two paths through a real gateway, which is
 * what establishes that those are in fact the sequences it publishes. This test fixes the branch
 * matrix around them, including the cases the gateway is awkward to push into.
 */
class GcpDeployTimeSecretRefsTest {

    private static final String API_V4 = "api-v4";
    private static final String NATIVE_API_V4 = "native-api-v4";
    private static final String API_ID = "deploy-time-unit";
    private static final String SECRET_REF = "secret://gcp/deploy-time-secret:value";
    private static final String ENV_ID = "DEFAULT";
    private static final String ENCODING_BASE64 = "base64";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Shape of a {@code transform-headers} configuration, the one the gateway integration test uses. */
    private static String configurationWith(String headerValue) {
        return "{\"addHeaders\":[{\"name\":\"X-Injected-Credential\",\"value\":\"%s\"}]}".formatted(headerValue);
    }

    private final AtomicReference<String> secretValue = new AtomicReference<>("secret-value-v1");
    private final AtomicReference<Maybe<byte[]>> secretResponse = new AtomicReference<>();

    private EventManagerImpl eventManager;
    private List<SecretDiscoveryEvent> valueChanged;
    private GcpDeployTimeSecretRefs substituter;

    @BeforeEach
    void setUp() {
        eventManager = new EventManagerImpl();
        valueChanged = new CopyOnWriteArrayList<>();
        eventManager.subscribeForEvents(
            event -> {
                if (event.content() instanceof SecretDiscoveryEvent discovery) {
                    valueChanged.add(discovery);
                }
            },
            SecretDiscoveryEventType.VALUE_CHANGED
        );
        substituter = armedSubstituter(true);
    }

    @AfterEach
    void tearDown() {
        substituter.destroy();
    }

    // ── Deploy ────────────────────────────────────────────────────────────────

    @Test
    void should_substitute_a_reference_and_leave_no_trace_of_it() {
        TestDefinition definition = deployed(API_V4, API_ID, "1");

        assertThat(definition.configuration).contains("secret-value-v1").doesNotContain(SECRET_REF);
    }

    @Test
    void should_be_inert_when_the_property_is_not_set() {
        substituter.destroy();
        // A fresh bus: destroy() shuts the rotation thread down but does not unsubscribe, so the
        // armed instance from setUp would otherwise still handle the DISCOVER published below.
        eventManager = new EventManagerImpl();
        substituter = armedSubstituter(false);

        TestDefinition definition = new TestDefinition(API_V4, API_ID, configurationWith(SECRET_REF));
        discover(definition, "1");

        assertThat(definition.configuration).as("nothing may be substituted with the feature off").contains(SECRET_REF);
    }

    /**
     * Fail closed. The alternative to failing the deployment is an API served with a literal
     * {@code secret://gcp/...} sitting in a credential field, which the far end answers with a 401 and
     * nobody notices.
     */
    @Test
    void should_fail_the_deployment_when_a_reference_cannot_be_resolved() {
        secretResponse.set(Maybe.empty());
        TestDefinition definition = new TestDefinition(API_V4, API_ID, configurationWith(SECRET_REF));

        assertThatThrownBy(() -> discover(definition, "1"))
            .hasMessageContaining(SECRET_REF)
            .hasMessageContaining("transform-headers");
    }

    /**
     * A secret containing a quote or a backslash lands inside a JSON string literal in the raw
     * configuration, so an unescaped value would break the payload the policy deserialises.
     */
    @Test
    void should_escape_a_secret_that_would_otherwise_break_out_of_the_json_string() throws Exception {
        secretValue.set("a\"b\\c\td");

        TestDefinition definition = deployed(API_V4, API_ID, "1");

        String value = MAPPER.readTree(definition.configuration).get("addHeaders").get(0).get("value").asText();
        assertThat(value).isEqualTo("a\"b\\c\td");
    }

    // ── The ?encoding= modifier ───────────────────────────────────────────────

    /**
     * The motivating case: a JWT plan's {@code resolverParameter}, where {@code JWKBuilder} tries
     * {@code Base64.getDecoder().decode(keyValue)} first and only falls back to raw bytes when that
     * throws — so a raw secret that happens to be valid base64 silently becomes the decoded bytes.
     */
    @Test
    void should_base64_encode_the_resolved_value_when_the_reference_asks_for_it() {
        secretValue.set("hmac-signing-key");

        TestDefinition definition = deployedWith(SECRET_REF + "?encoding=base64");

        assertThat(definition.configuration).contains(base64("hmac-signing-key")).doesNotContain("hmac-signing-key");
    }

    /** The encoding belongs to the field, so one stored secret has to be able to serve both forms. */
    @Test
    void should_encode_only_the_reference_that_asks_and_leave_a_sibling_raw() {
        secretValue.set("shared-key");
        TestDefinition definition = new TestDefinition(
            API_V4,
            API_ID,
            "{\"raw\":\"%s\",\"encoded\":\"%s?encoding=base64\"}".formatted(SECRET_REF, SECRET_REF)
        );

        discover(definition, "1");

        assertThat(definition.configuration).isEqualTo("{\"raw\":\"shared-key\",\"encoded\":\"%s\"}".formatted(base64("shared-key")));
    }

    /** A rotation has to carry the encoding with it, or the field reverts to raw on the next change. */
    @Test
    void should_keep_the_encoding_across_a_rotation() {
        secretValue.set("key-v1");
        TestDefinition definition = deployedWith(SECRET_REF + "?encoding=base64");

        rotateTo("key-v2");

        assertThat(definition.configuration).contains(base64("key-v2"));
        assertThat(valueChanged).hasSize(1);
    }

    @Test
    void should_reject_an_encoding_it_does_not_support() {
        TestDefinition definition = new TestDefinition(API_V4, API_ID, configurationWith(SECRET_REF + "?encoding=hex"));

        assertThatThrownBy(() -> discover(definition, "1"))
            .hasMessageContaining("encoding='hex'")
            .hasMessageContaining(ENCODING_BASE64);
    }

    @Test
    void should_reject_an_encoding_set_more_than_once() {
        TestDefinition definition = new TestDefinition(API_V4, API_ID, configurationWith(SECRET_REF + "?encoding=base64&encoding=base64"));

        assertThatThrownBy(() -> discover(definition, "1")).hasMessageContaining("at most once");
    }

    // ── Nothing is left in place silently ─────────────────────────────────────

    /**
     * The incident shape this guards against: a misspelled reference surviving into the deployed
     * definition as literal text, travelling upstream as a credential, and coming back as a 401 that
     * names nothing. A pattern matching only <em>valid</em> references would do exactly that.
     */
    @Test
    void should_reject_a_gcp_reference_it_cannot_parse() {
        TestDefinition definition = new TestDefinition(API_V4, API_ID, configurationWith("secret://gcp/"));

        assertThatThrownBy(() -> discover(definition, "1"))
            .hasMessageContaining("secret://gcp/")
            .hasMessageContaining("transform-headers");
    }

    @Test
    void should_reject_a_gcp_reference_whose_path_is_not_a_gcp_location() {
        TestDefinition definition = new TestDefinition(API_V4, API_ID, configurationWith("secret://gcp/project/secret/version:value"));

        assertThatThrownBy(() -> discover(definition, "1")).hasMessageContaining("transform-headers");
    }

    /**
     * A reference naming another provider is not ours to resolve, so it is left alone rather than
     * failing someone else's working gateway — but it must not vanish into the noise either, which is
     * why it is logged at WARN, the level that survives the gateway's default {@code root=WARN}.
     */
    @Test
    void should_leave_another_providers_reference_in_place_and_retain_nothing() {
        TestDefinition definition = new TestDefinition(API_V4, API_ID, configurationWith("secret://kubernetes/tls:crt"));

        discover(definition, "1");
        rotateTo("secret-value-v2");

        assertThat(definition.configuration).contains("secret://kubernetes/tls:crt");
        assertThat(valueChanged).as("nothing of ours was substituted, so nothing may be retained").isEmpty();
    }

    // ── Revoke ────────────────────────────────────────────────────────────────

    /**
     * The measurement the spike could not make. {@code update(api)} publishes DISCOVER for revision 2
     * and then REVOKE for revision 1; if that REVOKE releases the entry, rotation is dead from the
     * first redeploy onwards and nothing says so.
     */
    @Test
    void should_keep_the_live_entry_when_a_superseded_revision_is_revoked() {
        TestDefinition revision1 = deployed(API_V4, API_ID, "1");
        TestDefinition revision2 = deployed(API_V4, API_ID, "2");
        revoke(revision1, "1");

        rotateTo("secret-value-v2");

        assertThat(revision2.configuration).as("the live revision must still rotate").contains("secret-value-v2");
        assertThat(revision1.configuration).as("the superseded revision must not be written to").contains("secret-value-v1");
        assertThat(valueChanged).hasSize(1);
        assertThat(valueChanged.getFirst().definition()).isEqualTo(new Definition(API_V4, API_ID));
        assertThat(valueChanged.getFirst().metadata().revision()).isEqualTo("2");
    }

    /** {@code undeploy(apiId)} publishes REVOKE carrying the definition instance that was deployed. */
    @Test
    void should_release_the_entry_when_the_live_revision_is_revoked() {
        TestDefinition revision1 = deployed(API_V4, API_ID, "1");
        revoke(revision1, "1");

        rotateTo("secret-value-v2");

        assertThat(revision1.configuration).as("a revoked definition must not be rewritten").contains("secret-value-v1");
        assertThat(valueChanged).isEmpty();
    }

    /**
     * {@code ApiManagerImpl.refresh()} re-registers the <em>cached</em> api objects with
     * {@code force=true}, which republishes DISCOVER for the very instances already substituted. Their
     * references are gone because they were replaced, so a handler that treats "found nothing" as
     * "no longer needed" stops rotating after any gateway tag or configuration reload.
     */
    @Test
    void should_keep_the_entry_when_the_same_definition_instance_is_rediscovered() {
        TestDefinition revision1 = deployed(API_V4, API_ID, "1");
        discover(revision1, "1");

        rotateTo("secret-value-v2");

        assertThat(revision1.configuration).contains("secret-value-v2");
        assertThat(valueChanged).hasSize(1);
    }

    /**
     * The mirror case: a genuinely new revision that stopped referencing a secret. A forced
     * re-register goes through {@code deploy()}, which publishes no REVOKE, so DISCOVER is the only
     * chance to let go of the superseded entry.
     */
    @Test
    void should_release_a_superseded_entry_when_the_new_revision_references_no_secret() {
        TestDefinition revision1 = deployed(API_V4, API_ID, "1");
        TestDefinition revision2 = new TestDefinition(API_V4, API_ID, configurationWith("a-literal-value"));
        discover(revision2, "2");

        rotateTo("secret-value-v2");

        assertThat(revision1.configuration).contains("secret-value-v1");
        assertThat(revision2.configuration).contains("a-literal-value");
        assertThat(valueChanged).isEmpty();
    }

    /**
     * Ids are unique within a kind, not across them — which is why the retained map is keyed by
     * {@link Definition} rather than by id.
     */
    @Test
    void should_not_let_one_kind_revoke_another_kinds_definition_of_the_same_id() {
        TestDefinition proxyApi = deployed(API_V4, API_ID, "1");
        TestDefinition nativeApi = deployed(NATIVE_API_V4, API_ID, "1");
        revoke(proxyApi, "1");

        rotateTo("secret-value-v2");

        assertThat(proxyApi.configuration).contains("secret-value-v1");
        assertThat(nativeApi.configuration).contains("secret-value-v2");
        assertThat(valueChanged).hasSize(1);
        assertThat(valueChanged.getFirst().definition()).isEqualTo(new Definition(NATIVE_API_V4, API_ID));
    }

    /**
     * The revision comes from the optional {@code deployment_number} event property. With none set, a
     * revision-only comparison would match {@code null} against {@code null} and release the live
     * entry on the first redeploy; identity is what keeps this case correct.
     */
    @Test
    void should_keep_the_live_entry_when_no_revision_is_supplied_at_all() {
        TestDefinition revision1 = deployed(API_V4, API_ID, null);
        TestDefinition revision2 = deployed(API_V4, API_ID, null);
        revoke(revision1, null);

        rotateTo("secret-value-v2");

        assertThat(revision2.configuration).contains("secret-value-v2");
        assertThat(valueChanged).hasSize(1);
    }

    // ── Rotation ──────────────────────────────────────────────────────────────

    @Test
    void should_publish_nothing_when_the_value_has_not_moved() {
        deployed(API_V4, API_ID, "1");

        substituter.checkForRotations();

        assertThat(valueChanged).isEmpty();
    }

    /** One bad definition must not stop the scheduler resolving every other one. */
    @Test
    void should_survive_a_resolution_failure_during_a_rotation_check() {
        TestDefinition revision1 = deployed(API_V4, API_ID, "1");
        secretResponse.set(Maybe.error(new IllegalStateException("secret manager is down")));

        substituter.checkForRotations();

        assertThat(revision1.configuration).as("the value in force must stay").contains("secret-value-v1");
        assertThat(valueChanged).isEmpty();
    }

    // ── harness ──────────────────────────────────────────────────────────────

    /** Deploys a fresh definition instance, as the gateway does for every new revision. */
    private TestDefinition deployed(String kind, String id, String revision) {
        TestDefinition definition = new TestDefinition(kind, id, configurationWith(SECRET_REF));
        discover(definition, revision);
        return definition;
    }

    /** Deploys revision 1 of an API whose one field carries the given reference verbatim. */
    private TestDefinition deployedWith(String reference) {
        TestDefinition definition = new TestDefinition(API_V4, API_ID, configurationWith(reference));
        discover(definition, "1");
        return definition;
    }

    private static String base64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private void discover(TestDefinition definition, String revision) {
        eventManager.publishEvent(
            SecretDiscoveryEventType.DISCOVER,
            new SecretDiscoveryEvent(ENV_ID, definition, new DefinitionMetadata(revision))
        );
    }

    private void revoke(TestDefinition definition, String revision) {
        eventManager.publishEvent(
            SecretDiscoveryEventType.REVOKE,
            new SecretDiscoveryEvent(ENV_ID, definition, new DefinitionMetadata(revision))
        );
    }

    private void rotateTo(String newValue) {
        secretValue.set(newValue);
        substituter.checkForRotations();
    }

    private GcpDeployTimeSecretRefs armedSubstituter(boolean enabled) {
        GcpSecretManagerClient client = (secret, version) -> {
            Maybe<byte[]> stubbed = secretResponse.get();
            return stubbed != null ? stubbed : Maybe.just(secretValue.get().getBytes(StandardCharsets.UTF_8));
        };
        GcpConfig config = new GcpConfig(Map.of("enabled", true, "projectId", "example-project", "secretTtlSeconds", 300));
        /*
         * Fixed at the epoch deliberately. SecretMap#isExpired compares against Instant.now(), not
         * against this clock, so stamping expiry from 1970 makes every cached entry already stale and
         * every resolution go back to the stub — which is what lets a rotation be observed without
         * sleeping out a TTL. Do not "fix" this to Clock.systemUTC(): the cache would then serve the
         * old value and the rotation assertions would pass for the wrong reason.
         */
        CachingGcpSecretResolver resolver = new CachingGcpSecretResolver(client, config, Clock.fixed(Instant.EPOCH, ZoneOffset.UTC));

        GcpDeployTimeSecretRefs refs = new GcpDeployTimeSecretRefs(resolver);
        refs.setEnvironment(environmentWith(enabled));
        refs.setApplicationContext(contextWith(new TestFinder()));
        refs.postProcessAfterInitialization(eventManager, "eventManager");
        return refs;
    }

    private static StandardEnvironment environmentWith(boolean enabled) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put(GcpDeployTimeSecretRefs.DEPLOY_TIME_ENABLED_PROPERTY, String.valueOf(enabled));
        // Long enough that the scheduler never fires: every rotation here is driven explicitly.
        properties.put(GcpDeployTimeSecretRefs.ROTATION_CHECK_SECONDS_PROPERTY, "3600");
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("deploy-time", properties));
        return environment;
    }

    private static ApplicationContext contextWith(DefinitionSecretRefsFinder<?> finder) {
        ApplicationContext context = mock(ApplicationContext.class);
        // doReturn rather than when(...).thenReturn(...): getBeansOfType is generic in its argument,
        // and a raw finder map is not assignable to the inferred Map<String, T>.
        doReturn(Map.of("testFinder", finder)).when(context).getBeansOfType(DefinitionSecretRefsFinder.class);
        return context;
    }

    /**
     * Stands in for a V4 {@code Api}: a kind, an id, and one raw plugin configuration payload. Using a
     * local type rather than the real definition model keeps this test off APIM's internals — the real
     * {@code ApiV4DefinitionSecretRefsFinder} is exercised by the gateway integration tests, which is
     * where a change in its walk would show up.
     */
    private static final class TestDefinition {

        private final String kind;
        private final String id;
        private String configuration;

        private TestDefinition(String kind, String id, String configuration) {
            this.kind = kind;
            this.id = id;
            this.configuration = configuration;
        }
    }

    /** Mirrors {@code AbstractV4APISecretRefFinder.processStep}: the whole payload, and a setter. */
    private static final class TestFinder implements DefinitionSecretRefsFinder<TestDefinition> {

        @Override
        public boolean canHandle(Object definition) {
            return definition instanceof TestDefinition;
        }

        @Override
        public DefinitionDescriptor toDefinitionDescriptor(TestDefinition definition, DefinitionMetadata metadata) {
            return new DefinitionDescriptor(new Definition(definition.kind, definition.id), Optional.ofNullable(metadata.revision()));
        }

        @Override
        public void findSecretRefs(TestDefinition definition, DefinitionSecretRefsListener listener) {
            listener.onCandidate(
                definition.configuration,
                new SecretRefsLocation(SecretRefsLocation.PLUGIN_KIND, "transform-headers"),
                updated -> definition.configuration = updated
            );
        }
    }
}
