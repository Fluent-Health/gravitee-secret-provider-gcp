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

import io.fluenthealth.gravitee.secretprovider.gcp.core.CachingGcpSecretResolver;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpConfig;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpSecretManagerClient;
import io.gravitee.secrets.api.errors.SecretManagerException;
import io.reactivex.rxjava3.core.Maybe;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class GcpSecretsElHolderTest {

    /*
     * A system clock, deliberately, not a fixed one. The cache decides staleness with
     * SecretMap#isExpired, which compares against Instant.now() and takes no injected clock — so a
     * clock fixed at some instant T makes every cache entry expire in wall-clock terms once the real
     * time passes T + ttl. A fixed 2026-07-29T12:00:00Z with the 300s TTL below did exactly that:
     * green all morning, then failing from 12:05Z onwards. A time bomb, not a flake.
     *
     * Tests that need an entry to be expired stamp their own clock in the past instead — see
     * should_refetch_once_the_ttl_has_lapsed_so_a_rotation_is_picked_up.
     */
    private static final Clock CLOCK = Clock.systemUTC();
    private static final GcpConfig CONFIG = new GcpConfig(Map.of("enabled", true, "projectId", "example-project", "secretTtlSeconds", 300));

    private final List<String> requested = new ArrayList<>();

    private GcpSecretsElHolder holderReturning(String payload) {
        GcpSecretManagerClient client = (secret, version) -> {
            requested.add(secret + "/" + version);
            return Maybe.just(payload.getBytes(StandardCharsets.UTF_8));
        };
        return new GcpSecretsElHolder(new CachingGcpSecretResolver(client, CONFIG, CLOCK));
    }

    @Test
    void should_resolve_a_key_from_a_json_secret_using_the_enterprise_uri_syntax() {
        GcpSecretsElHolder holder = holderReturning("{\"username\":\"apim\",\"password\":\"s3cr3t\"}");

        String value = holder
            .get("/gcp/db-credentials:password")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(value).isEqualTo("s3cr3t");
        assertThat(requested).containsExactly("db-credentials/latest");
    }

    @Test
    void should_resolve_an_opaque_secret_without_a_key() {
        GcpSecretsElHolder holder = holderReturning("plain-token");

        String value = holder.get("/gcp/api-token").test().awaitDone(5, TimeUnit.SECONDS).assertComplete().values().getFirst();

        assertThat(value).isEqualTo("plain-token");
    }

    @Test
    void should_accept_the_key_as_a_separate_argument() {
        GcpSecretsElHolder holder = holderReturning("{\"username\":\"apim\",\"password\":\"s3cr3t\"}");

        String value = holder
            .get("/gcp/db-credentials", "username")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(value).isEqualTo("apim");
    }

    @Test
    void should_resolve_a_pinned_version() {
        GcpSecretsElHolder holder = holderReturning("v7");

        holder.get("/gcp/db-password/7:value").test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        assertThat(requested).containsExactly("db-password/7");
    }

    @Test
    void should_serve_a_second_read_from_cache_within_the_ttl() {
        GcpSecretsElHolder holder = holderReturning("{\"password\":\"s3cr3t\"}");

        holder.get("/gcp/db-credentials:password").test().awaitDone(5, TimeUnit.SECONDS).assertComplete();
        holder.get("/gcp/db-credentials:password").test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        assertThat(requested).hasSize(1);
    }

    @Test
    void should_refetch_once_the_ttl_has_lapsed_so_a_rotation_is_picked_up() {
        /*
         * SecretMap#isExpired compares against Instant.now(), not against any injected clock, so
         * expiry is forced by stamping the entry with a TTL that has already elapsed in wall-clock
         * terms: a clock fixed in the past plus a 1s TTL.
         */
        Clock clockInThePast = Clock.fixed(Instant.parse("2020-01-01T00:00:00Z"), ZoneOffset.UTC);
        GcpSecretManagerClient client = (secret, version) -> {
            requested.add(secret + "/" + version);
            return Maybe.just("{\"password\":\"s3cr3t\"}".getBytes(StandardCharsets.UTF_8));
        };
        GcpConfig shortTtl = new GcpConfig(Map.of("enabled", true, "projectId", "example-project", "secretTtlSeconds", 1));
        GcpSecretsElHolder holder = new GcpSecretsElHolder(new CachingGcpSecretResolver(client, shortTtl, clockInThePast));

        holder.get("/gcp/db-credentials:password").test().awaitDone(5, TimeUnit.SECONDS).assertComplete();
        holder.get("/gcp/db-credentials:password").test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        assertThat(requested).hasSize(2);
    }

    @Test
    void should_reject_a_bare_name_because_there_is_no_spec_registry_without_the_enterprise_service() {
        GcpSecretsElHolder holder = holderReturning("x");

        holder
            .get("db-credentials")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertError(SecretManagerException.class)
            .assertError(error -> error.getMessage().contains("is not a secret URI"));
    }

    @Test
    void should_reject_a_uri_for_another_provider() {
        GcpSecretsElHolder holder = holderReturning("x");

        holder
            .get("/vault/secret/test:value1")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertError(SecretManagerException.class)
            .assertError(error -> error.getMessage().contains("vault"));
    }

    @Test
    void should_fail_with_the_available_keys_when_the_requested_key_is_absent() {
        GcpSecretsElHolder holder = holderReturning("{\"username\":\"apim\"}");

        holder
            .get("/gcp/db-credentials:password")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertError(SecretManagerException.class)
            .assertError(error -> error.getMessage().contains("username"));
    }

    @Test
    void should_fail_when_the_secret_does_not_exist() {
        GcpSecretManagerClient absent = (secret, version) -> Maybe.empty();
        GcpSecretsElHolder holder = new GcpSecretsElHolder(new CachingGcpSecretResolver(absent, CONFIG, CLOCK));

        holder
            .get("/gcp/nope:key")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertError(SecretManagerException.class)
            .assertError(error -> error.getMessage().contains("does not exist"));
    }

    @Test
    void should_not_touch_secret_manager_until_the_single_is_subscribed_to() {
        GcpSecretsElHolder holder = holderReturning("{\"password\":\"s3cr3t\"}");

        holder.get("/gcp/db-credentials:password");

        assertThat(requested).isEmpty();
    }

    @Test
    void should_reject_an_empty_uri() {
        GcpSecretsElHolder holder = holderReturning("x");

        holder.get("  ").test().awaitDone(5, TimeUnit.SECONDS).assertError(SecretManagerException.class);
    }

    // ── basic() ──────────────────────────────────────────────────────────────

    @Test
    void should_build_a_complete_basic_credential_from_the_resolved_secret() {
        GcpSecretsElHolder holder = holderReturning("s3cr3t");

        String value = holder
            .basic("/gcp/emr-bots-client-secret:value", "emr-bots")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(value).isEqualTo("Basic " + Base64.getEncoder().encodeToString("emr-bots:s3cr3t".getBytes(StandardCharsets.UTF_8)));
        assertThat(value).isEqualTo("Basic ZW1yLWJvdHM6czNjcjN0");
        assertThat(requested).containsExactly("emr-bots-client-secret/latest");
    }

    @Test
    void should_read_the_password_out_of_a_json_secret_by_key() {
        GcpSecretsElHolder holder = holderReturning("{\"username\":\"ignored\",\"password\":\"s3cr3t\"}");

        String value = holder
            .basic("/gcp/db-credentials:password", "apim")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(value).isEqualTo("Basic " + Base64.getEncoder().encodeToString("apim:s3cr3t".getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * The platform default charset would make the header depend on the gateway's locale, so a
     * non-ASCII password could encode differently from one node to the next.
     */
    @Test
    void should_encode_the_credential_as_utf8_regardless_of_the_platform_default() {
        GcpSecretsElHolder holder = holderReturning("pä§§word-€");

        String value = holder
            .basic("/gcp/unicode-secret:value", "üser")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(value).isEqualTo("Basic " + Base64.getEncoder().encodeToString("üser:pä§§word-€".getBytes(StandardCharsets.UTF_8)));
        assertThat(Base64.getDecoder().decode(value.substring("Basic ".length()))).isEqualTo(
            "üser:pä§§word-€".getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * RFC 7617, not RFC 6749 §2.3.1: the components are joined verbatim. Encoding them here would
     * silently corrupt every existing Basic header whose password contains a reserved character.
     */
    @Test
    void should_not_url_encode_the_components() {
        GcpSecretsElHolder holder = holderReturning("secret:with/slash+plus space");

        String value = holder
            .basic("/gcp/reserved-chars:value", "id with space")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        String decoded = new String(Base64.getDecoder().decode(value.substring("Basic ".length())), StandardCharsets.UTF_8);
        assertThat(decoded).isEqualTo("id with space:secret:with/slash+plus space");
    }

    @Test
    void should_reject_a_blank_user_name_rather_than_send_half_a_credential() {
        GcpSecretsElHolder holder = holderReturning("s3cr3t");

        holder.basic("/gcp/db-credentials:password", "  ").test().awaitDone(5, TimeUnit.SECONDS).assertError(SecretManagerException.class);
        holder.basic("/gcp/db-credentials:password", null).test().awaitDone(5, TimeUnit.SECONDS).assertError(SecretManagerException.class);

        assertThat(requested).as("must fail before reaching Secret Manager").isEmpty();
    }

    @Test
    void should_reject_an_empty_uri_naming_basic_in_the_message() {
        GcpSecretsElHolder holder = holderReturning("x");

        holder
            .basic("  ", "apim")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertError(t -> t.getMessage() != null && t.getMessage().contains("#secrets.basic"));
    }

    @Test
    void should_propagate_a_resolution_failure_from_basic() {
        GcpSecretsElHolder holder = holderReturning("{\"username\":\"apim\"}");

        holder
            .basic("/gcp/db-credentials:password", "apim")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertError(t -> t.getMessage() != null && t.getMessage().contains("db-credentials"));
    }

    @Test
    void should_not_touch_secret_manager_until_the_basic_single_is_subscribed_to() {
        GcpSecretsElHolder holder = holderReturning("s3cr3t");

        holder.basic("/gcp/db-credentials:password", "apim");

        assertThat(requested).isEmpty();
    }
}
