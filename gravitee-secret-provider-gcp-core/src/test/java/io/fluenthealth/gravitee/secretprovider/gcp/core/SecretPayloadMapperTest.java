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
package io.fluenthealth.gravitee.secretprovider.gcp.core;

import static org.assertj.core.api.Assertions.assertThat;

import io.gravitee.secrets.api.core.SecretMap;
import io.gravitee.secrets.api.core.SecretURL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * A GCP secret payload is a single opaque blob, unlike a Kubernetes secret which is natively a
 * key/value map. These tests pin the convention that bridges the two.
 */
class SecretPayloadMapperTest {

    private static final Instant EXPIRES_AT = Instant.parse("2026-07-29T12:00:00Z");

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void should_expose_a_flat_json_object_as_the_secret_map() {
        SecretURL url = SecretURL.from("secret://gcp/db-credentials:username");

        SecretMap secretMap = SecretPayloadMapper.toSecretMap(bytes("{\"username\":\"apim\",\"password\":\"s3cr3t\"}"), url, EXPIRES_AT);

        assertThat(secretMap.asMap()).containsOnlyKeys("username", "password");
        assertThat(secretMap.getSecret(url))
            .isPresent()
            .get()
            .extracting(secret -> secret.asString())
            .isEqualTo("apim");
    }

    @Test
    void should_stringify_non_string_json_scalars() {
        SecretURL url = SecretURL.from("secret://gcp/tuning:port");

        SecretMap secretMap = SecretPayloadMapper.toSecretMap(bytes("{\"port\":5432,\"tls\":true}"), url, EXPIRES_AT);

        assertThat(secretMap.getSecret(url))
            .isPresent()
            .get()
            .extracting(secret -> secret.asString())
            .isEqualTo("5432");
    }

    @Test
    void should_treat_a_nested_json_object_as_opaque_because_the_secret_map_is_flat() {
        SecretURL url = SecretURL.from("secret://gcp/config:value");
        String payload = "{\"outer\":{\"inner\":\"x\"}}";

        SecretMap secretMap = SecretPayloadMapper.toSecretMap(bytes(payload), url, EXPIRES_AT);

        assertThat(secretMap.asMap()).containsOnlyKeys("value");
        assertThat(secretMap.getSecret(url))
            .isPresent()
            .get()
            .extracting(secret -> secret.asString())
            .isEqualTo(payload);
    }

    @Test
    void should_expose_an_opaque_payload_under_the_key_from_the_url() {
        SecretURL url = SecretURL.from("secret://gcp/api-token:token");

        SecretMap secretMap = SecretPayloadMapper.toSecretMap(bytes("not-json-at-all"), url, EXPIRES_AT);

        assertThat(secretMap.asMap()).containsOnlyKeys("token");
        assertThat(secretMap.getSecret(url))
            .isPresent()
            .get()
            .extracting(secret -> secret.asString())
            .isEqualTo("not-json-at-all");
    }

    @Test
    void should_default_the_key_to_value_when_the_url_has_none() {
        SecretURL url = SecretURL.from("secret://gcp/api-token");

        SecretMap secretMap = SecretPayloadMapper.toSecretMap(bytes("opaque"), url, EXPIRES_AT);

        assertThat(secretMap.asMap()).containsOnlyKeys(SecretPayloadMapper.DEFAULT_KEY);
    }

    @Test
    void should_carry_the_expiry_so_the_ee_service_and_our_cache_can_renew() {
        SecretURL url = SecretURL.from("secret://gcp/api-token:token");

        SecretMap secretMap = SecretPayloadMapper.toSecretMap(bytes("opaque"), url, EXPIRES_AT);

        assertThat(secretMap.expiresAt()).contains(EXPIRES_AT);
    }

    @Test
    void should_map_conventional_key_names_to_well_known_keys_for_tls_and_credentials() {
        SecretURL url = SecretURL.from("secret://gcp/db-credentials:password");

        SecretMap secretMap = SecretPayloadMapper.toSecretMap(bytes("{\"username\":\"apim\",\"password\":\"s3cr3t\"}"), url, EXPIRES_AT);

        assertThat(secretMap.wellKnown(SecretMap.WellKnownSecretKey.USERNAME))
            .isPresent()
            .get()
            .extracting(secret -> secret.asString())
            .isEqualTo("apim");
        assertThat(secretMap.wellKnown(SecretMap.WellKnownSecretKey.PASSWORD))
            .isPresent()
            .get()
            .extracting(secret -> secret.asString())
            .isEqualTo("s3cr3t");
    }

    @Test
    void should_let_an_explicit_keymap_override_the_default_well_known_mapping() {
        SecretURL url = SecretURL.from("secret://gcp/tls-bundle:crt?keymap=certificate:crt&keymap=private_key:pk");

        SecretMap secretMap = SecretPayloadMapper.toSecretMap(bytes("{\"crt\":\"---cert---\",\"pk\":\"---key---\"}"), url, EXPIRES_AT);

        assertThat(secretMap.wellKnown(SecretMap.WellKnownSecretKey.CERTIFICATE))
            .isPresent()
            .get()
            .extracting(secret -> secret.asString())
            .isEqualTo("---cert---");
        assertThat(secretMap.wellKnown(SecretMap.WellKnownSecretKey.PRIVATE_KEY))
            .isPresent()
            .get()
            .extracting(secret -> secret.asString())
            .isEqualTo("---key---");
    }

    @Test
    void should_not_treat_a_json_array_as_a_secret_map() {
        SecretURL url = SecretURL.from("secret://gcp/list:value");

        SecretMap secretMap = SecretPayloadMapper.toSecretMap(bytes("[1,2,3]"), url, EXPIRES_AT);

        assertThat(secretMap.asMap()).containsOnlyKeys("value");
        assertThat(secretMap.getSecret(url))
            .isPresent()
            .get()
            .extracting(secret -> secret.asString())
            .isEqualTo("[1,2,3]");
    }
}
