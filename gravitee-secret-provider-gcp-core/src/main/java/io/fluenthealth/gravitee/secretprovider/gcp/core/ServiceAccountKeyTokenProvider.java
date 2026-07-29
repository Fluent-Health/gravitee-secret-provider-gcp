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

import io.gravitee.secrets.api.errors.SecretManagerException;
import io.reactivex.rxjava3.core.Single;
import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.rxjava3.ext.web.client.HttpResponse;
import io.vertx.rxjava3.ext.web.client.WebClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.Objects;

/**
 * Obtains an access token by signing a JWT with a downloaded service account key
 * (RFC 7523 {@code jwt-bearer} grant).
 *
 * <p><strong>Local development only.</strong> Production runs on Workload Identity via
 * {@link MetadataServerTokenProvider} — a key file is long-lived static credential material, which
 * is the thing this whole plugin exists to stop us shipping around. It is supported only so a
 * developer can point a gateway on their laptop at a real project.
 *
 * <p>Tokens are <em>not</em> cached here — wrap this in a {@link CachingAccessTokenProvider}.
 */
public class ServiceAccountKeyTokenProvider implements GcpAccessTokenProvider {

    private static final String CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
    private static final String JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private static final String DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";
    private static final long ASSERTION_LIFETIME_SECONDS = 3600;

    private final WebClient webClient;
    private final GcpConfig config;
    private final Clock clock;
    private final String clientEmail;
    private final String tokenUri;
    private final PrivateKey privateKey;

    public ServiceAccountKeyTokenProvider(WebClient webClient, GcpConfig config, Clock clock) {
        this.webClient = Objects.requireNonNull(webClient);
        this.config = Objects.requireNonNull(config);
        this.clock = Objects.requireNonNull(clock);

        JsonObject key = readKeyFile(config.serviceAccountKeyFile());
        this.clientEmail = require(key, "client_email", config.serviceAccountKeyFile());
        this.tokenUri = key.getString("token_uri", DEFAULT_TOKEN_URI);
        this.privateKey = parsePrivateKey(require(key, "private_key", config.serviceAccountKeyFile()));
    }

    @Override
    public Single<GcpAccessToken> token() {
        return Single.fromCallable(this::signedAssertion)
            .flatMap(assertion ->
                webClient
                    .postAbs(tokenUri)
                    .timeout(config.requestTimeoutMs())
                    .sendForm(MultiMap.caseInsensitiveMultiMap().set("grant_type", JWT_BEARER_GRANT).set("assertion", assertion))
            )
            .map(this::toToken)
            .onErrorResumeNext(error -> Single.error(wrap(error)));
    }

    private GcpAccessToken toToken(HttpResponse<Buffer> response) {
        if (response.statusCode() != 200) {
            throw new SecretManagerException(
                "GCP token endpoint %s returned HTTP %d for service account '%s': %s".formatted(
                    tokenUri,
                    response.statusCode(),
                    clientEmail,
                    response.bodyAsString()
                )
            );
        }
        JsonObject body = response.bodyAsJsonObject();
        String accessToken = body == null ? null : body.getString("access_token");
        if (accessToken == null || accessToken.isBlank()) {
            throw new SecretManagerException("GCP token endpoint response contained no 'access_token'");
        }
        return new GcpAccessToken(accessToken, clock.instant().plusSeconds(body.getLong("expires_in", 0L)));
    }

    private String signedAssertion() throws Exception {
        long issuedAt = clock.instant().getEpochSecond();
        String header = base64Url(new JsonObject().put("alg", "RS256").put("typ", "JWT").encode());
        String claims = base64Url(
            new JsonObject()
                .put("iss", clientEmail)
                .put("scope", CLOUD_PLATFORM_SCOPE)
                .put("aud", tokenUri)
                .put("iat", issuedAt)
                .put("exp", issuedAt + ASSERTION_LIFETIME_SECONDS)
                .encode()
        );
        String signingInput = header + "." + claims;

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static JsonObject readKeyFile(String path) {
        try {
            return new JsonObject(Files.readString(Path.of(path), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new SecretManagerException("Could not read the GCP service account key file at '%s'".formatted(path), e);
        }
    }

    private static String require(JsonObject key, String field, String path) {
        String value = key.getString(field);
        if (value == null || value.isBlank()) {
            throw new SecretManagerException("GCP service account key file '%s' has no '%s'".formatted(path, field));
        }
        return value;
    }

    private static PrivateKey parsePrivateKey(String pem) {
        String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
        } catch (Exception e) {
            throw new SecretManagerException("The 'private_key' in the GCP service account key file is not a PKCS#8 RSA key", e);
        }
    }

    private Throwable wrap(Throwable error) {
        if (error instanceof SecretManagerException) {
            return error;
        }
        return new SecretManagerException("Could not obtain a GCP access token for service account '%s'".formatted(clientEmail), error);
    }
}
