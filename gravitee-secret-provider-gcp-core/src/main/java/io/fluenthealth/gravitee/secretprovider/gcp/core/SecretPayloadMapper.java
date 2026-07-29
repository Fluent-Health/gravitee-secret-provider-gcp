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

import io.gravitee.secrets.api.core.SecretMap;
import io.gravitee.secrets.api.core.SecretURL;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Turns a GCP Secret Manager payload into a Gravitee {@link SecretMap}.
 *
 * <p>The two models do not line up: a Kubernetes secret — the shape the rest of Gravitee is built
 * around — is natively a key/value map, whereas a GCP secret version is one opaque blob. The
 * convention implemented here bridges them:
 *
 * <ul>
 *   <li>If the payload parses as a <em>flat</em> JSON object, it becomes the secret map directly,
 *       so one GCP secret can hold a whole credential set.
 *   <li>Otherwise the payload is opaque and is exposed whole, under the key named in the secret URL
 *       ({@code ...:<key>}), defaulting to {@value #DEFAULT_KEY}.
 * </ul>
 *
 * <p>"Flat" excludes nested objects and arrays: a {@link SecretMap} is a single-level
 * {@code String -> Secret} map, so there is nowhere for nested values to go. Rather than flatten
 * with some invented path syntax, such a payload is treated as opaque and handed over intact.
 */
public final class SecretPayloadMapper {

    /** Key used for an opaque payload when the secret URL names none. */
    public static final String DEFAULT_KEY = "value";

    /**
     * Applied when the URL carries no explicit {@code keymap}. GCP has no convention of its own for
     * these, so this covers the names most commonly used in practice, including the Kubernetes
     * {@code tls.crt} / {@code tls.key} spellings for secrets migrated across.
     */
    private static final Map<String, SecretMap.WellKnownSecretKey> DEFAULT_WELL_KNOWN_KEYS = Map.of(
        "username",
        SecretMap.WellKnownSecretKey.USERNAME,
        "password",
        SecretMap.WellKnownSecretKey.PASSWORD,
        "certificate",
        SecretMap.WellKnownSecretKey.CERTIFICATE,
        "tls.crt",
        SecretMap.WellKnownSecretKey.CERTIFICATE,
        "private_key",
        SecretMap.WellKnownSecretKey.PRIVATE_KEY,
        "tls.key",
        SecretMap.WellKnownSecretKey.PRIVATE_KEY
    );

    private SecretPayloadMapper() {}

    /**
     * @param payload the decoded secret version payload
     * @param secretURL the URL the payload was resolved for; supplies the opaque key and any
     *     {@code keymap} query parameter
     * @param expiresAt when the resulting map should be considered stale, which is what triggers
     *     re-resolution and therefore how rotation is picked up; may be {@code null}
     */
    public static SecretMap toSecretMap(byte[] payload, SecretURL secretURL, Instant expiresAt) {
        SecretMap secretMap = asFlatJsonObject(payload)
            .map(json -> SecretMap.of(stringValues(json), expiresAt))
            .orElseGet(() -> SecretMap.of(Map.of(opaqueKey(secretURL), payload), expiresAt));

        Map<String, SecretMap.WellKnownSecretKey> keyMap = secretURL == null ? Map.of() : secretURL.wellKnowKeyMap();
        return secretMap.handleWellKnownSecretKeys(keyMap.isEmpty() ? DEFAULT_WELL_KNOWN_KEYS : keyMap);
    }

    private static String opaqueKey(SecretURL secretURL) {
        return secretURL == null || secretURL.isKeyEmpty() ? DEFAULT_KEY : secretURL.key();
    }

    private static java.util.Optional<JsonObject> asFlatJsonObject(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return java.util.Optional.empty();
        }
        try {
            Object decoded = Json.decodeValue(Buffer.buffer(payload));
            if (decoded instanceof JsonObject json && isFlat(json)) {
                return java.util.Optional.of(json);
            }
        } catch (DecodeException e) {
            // Not JSON: an opaque payload is the normal case, not an error.
        }
        return java.util.Optional.empty();
    }

    private static boolean isFlat(JsonObject json) {
        return (
            !json.isEmpty() &&
            json
                .stream()
                .noneMatch(
                    entry ->
                        entry.getValue() == null ||
                        entry.getValue() instanceof JsonObject ||
                        entry.getValue() instanceof io.vertx.core.json.JsonArray
                )
        );
    }

    /**
     * Values are stringified because a {@link SecretMap} holds {@code String}/{@code byte[]} only;
     * a JSON number or boolean in a credential blob is still consumed as text.
     */
    private static Map<String, Object> stringValues(JsonObject json) {
        Map<String, Object> values = new LinkedHashMap<>();
        json.forEach(entry -> values.put(entry.getKey(), String.valueOf(entry.getValue())));
        return values;
    }
}
