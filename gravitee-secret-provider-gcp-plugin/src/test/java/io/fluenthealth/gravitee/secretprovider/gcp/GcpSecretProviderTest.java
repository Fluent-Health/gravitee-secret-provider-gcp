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
package io.fluenthealth.gravitee.secretprovider.gcp;

import static org.assertj.core.api.Assertions.assertThat;

import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpConfig;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpSecretManagerClient;
import io.gravitee.secrets.api.core.SecretMap;
import io.gravitee.secrets.api.core.SecretURL;
import io.gravitee.secrets.api.errors.SecretManagerException;
import io.reactivex.rxjava3.core.Maybe;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class GcpSecretProviderTest {

    private static final Instant NOW = Instant.parse("2026-07-29T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private record Call(String secret, String version) {}

    /** Records what was asked for and replies with a fixed payload. */
    private static final class RecordingClient implements GcpSecretManagerClient {

        private final List<Call> calls = new ArrayList<>();
        private final Maybe<byte[]> response;

        private RecordingClient(Maybe<byte[]> response) {
            this.response = response;
        }

        static RecordingClient returning(String payload) {
            return new RecordingClient(Maybe.just(payload.getBytes(StandardCharsets.UTF_8)));
        }

        @Override
        public Maybe<byte[]> accessSecretVersion(String secretName, String version) {
            calls.add(new Call(secretName, version));
            return response;
        }
    }

    private static GcpConfig config(Map<String, Object> overrides) {
        Map<String, Object> conf = new java.util.HashMap<>(Map.of("enabled", true, "projectId", "example-project"));
        conf.putAll(overrides);
        return new GcpConfig(conf);
    }

    private static GcpSecretProvider provider(GcpSecretManagerClient client, GcpConfig config) {
        return new GcpSecretProvider(config, client, CLOCK, null);
    }

    @Test
    void should_resolve_an_opaque_secret_under_the_key_from_the_url() {
        RecordingClient client = RecordingClient.returning("hunter2");
        SecretURL url = SecretURL.from("secret://gcp/db-password:password");

        SecretMap secretMap = provider(client, config(Map.of()))
            .resolve(url)
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(client.calls).containsExactly(new Call("db-password", "latest"));
        assertThat(secretMap.getSecret(url))
            .isPresent()
            .get()
            .extracting(secret -> secret.asString())
            .isEqualTo("hunter2");
    }

    @Test
    void should_resolve_a_json_secret_as_a_map() {
        RecordingClient client = RecordingClient.returning("{\"username\":\"apim\",\"password\":\"s3cr3t\"}");
        SecretURL url = SecretURL.from("secret://gcp/db-credentials:username");

        SecretMap secretMap = provider(client, config(Map.of()))
            .resolve(url)
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(secretMap.asMap()).containsOnlyKeys("username", "password");
    }

    @Test
    void should_request_the_pinned_version_named_in_the_url() {
        RecordingClient client = RecordingClient.returning("v7");

        provider(client, config(Map.of()))
            .resolve(SecretURL.from("secret://gcp/db-password/7:password"))
            .test()
            .awaitDone(5, TimeUnit.SECONDS);

        assertThat(client.calls).containsExactly(new Call("db-password", "7"));
    }

    @Test
    void should_set_an_expiry_on_a_floating_version_so_a_rotation_is_picked_up() {
        RecordingClient client = RecordingClient.returning("hunter2");

        SecretMap secretMap = provider(client, config(Map.of("secretTtlSeconds", 120)))
            .resolve(SecretURL.from("secret://gcp/db-password:password"))
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .values()
            .getFirst();

        assertThat(secretMap.expiresAt()).contains(NOW.plusSeconds(120));
    }

    @Test
    void should_not_expire_a_pinned_version_because_gcp_secret_versions_are_immutable() {
        RecordingClient client = RecordingClient.returning("v7");

        SecretMap secretMap = provider(client, config(Map.of("secretTtlSeconds", 120)))
            .resolve(SecretURL.from("secret://gcp/db-password/7:password"))
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .values()
            .getFirst();

        assertThat(secretMap.expiresAt()).isEmpty();
    }

    @Test
    void should_complete_empty_for_a_missing_secret() {
        GcpSecretManagerClient missing = (secret, version) -> Maybe.empty();

        provider(missing, config(Map.of()))
            .resolve(SecretURL.from("secret://gcp/absent:key"))
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .assertNoValues();
    }

    @Test
    void should_propagate_a_secret_manager_failure() {
        GcpSecretManagerClient failing = (secret, version) -> Maybe.error(new SecretManagerException("denied"));

        provider(failing, config(Map.of()))
            .resolve(SecretURL.from("secret://gcp/db-password:password"))
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertError(SecretManagerException.class);
    }

    @Test
    void should_treat_watch_as_a_no_op_rather_than_an_error() {
        RecordingClient client = RecordingClient.returning("hunter2");

        provider(client, config(Map.of()))
            .watch(SecretURL.from("secret://gcp/db-password:password?watch=true"))
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .assertNoValues();

        assertThat(client.calls).isEmpty();
    }

    @Test
    void should_release_owned_resources_on_stop() {
        boolean[] closed = { false };
        GcpSecretProvider provider = new GcpSecretProvider(config(Map.of()), RecordingClient.returning("x"), CLOCK, () -> closed[0] = true);

        assertThat(provider.stop()).isSameAs(provider);
        assertThat(closed[0]).isTrue();
    }

    @Test
    void should_not_fail_stop_when_releasing_resources_throws() {
        GcpSecretProvider provider = new GcpSecretProvider(config(Map.of()), RecordingClient.returning("x"), CLOCK, () -> {
            throw new IllegalStateException("already gone");
        });

        assertThat(provider.stop()).isSameAs(provider);
    }
}
