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
import io.reactivex.rxjava3.core.Maybe;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.rxjava3.ext.web.client.HttpResponse;
import io.vertx.rxjava3.ext.web.client.WebClient;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

/**
 * Secret Manager client built on the REST API and the Vert.x {@link WebClient} the gateway already
 * ships.
 *
 * <p>The alternative, {@code google-cloud-secretmanager}, would pull a gRPC/protobuf/Guava tree into
 * the plugin ZIP's {@code lib/}, where it competes with the gateway's own Guava and Netty inside an
 * isolated plugin classloader. One REST call needs none of that.
 */
public class RestGcpSecretManagerClient implements GcpSecretManagerClient {

    private final WebClient webClient;
    private final GcpConfig config;
    private final GcpAccessTokenProvider tokenProvider;

    public RestGcpSecretManagerClient(WebClient webClient, GcpConfig config, GcpAccessTokenProvider tokenProvider) {
        this.webClient = Objects.requireNonNull(webClient);
        this.config = Objects.requireNonNull(config);
        this.tokenProvider = Objects.requireNonNull(tokenProvider);
    }

    @Override
    public Maybe<byte[]> accessSecretVersion(String secretName, String version) {
        String url = accessUrl(secretName, version);
        return tokenProvider
            .token()
            .flatMapMaybe(token ->
                webClient
                    .getAbs(url)
                    .putHeader("Authorization", "Bearer " + token.value())
                    .timeout(config.requestTimeoutMs())
                    .send()
                    .flatMapMaybe(response -> toPayload(response, secretName, version))
            )
            .onErrorResumeNext(error -> Maybe.error(wrap(secretName, version, error)));
    }

    private String accessUrl(String secretName, String version) {
        return "%s/v1/projects/%s/secrets/%s/versions/%s:access".formatted(
            config.secretManagerBaseUrl(),
            encode(config.projectId()),
            encode(secretName),
            encode(version)
        );
    }

    /**
     * GCP secret names are restricted to {@code [A-Za-z0-9_-]}, so this is defence in depth: a name
     * that arrived from a secret URL must not be able to introduce extra path segments or a query
     * string into the request we make.
     */
    private static String encode(String segment) {
        return URLEncoder.encode(segment, StandardCharsets.UTF_8);
    }

    private Maybe<byte[]> toPayload(HttpResponse<Buffer> response, String secretName, String version) {
        return switch (response.statusCode()) {
            // Absence is a normal outcome the SPI models as an empty Maybe, not an error.
            case 200 -> Maybe.just(decodePayload(response, secretName));
            case 404 -> Maybe.empty();
            case 401, 403 -> Maybe.error(
                new SecretManagerException(
                    ("Access to GCP secret '%s' (version %s) in project '%s' was denied (HTTP %d). Grant " +
                        "roles/secretmanager.secretAccessor on the secret to the service account the gateway runs as. " +
                        "Response: %s").formatted(secretName, version, config.projectId(), response.statusCode(), response.bodyAsString())
                )
            );
            default -> Maybe.error(
                new SecretManagerException(
                    "GCP Secret Manager returned HTTP %d for secret '%s' (version %s): %s".formatted(
                        response.statusCode(),
                        secretName,
                        version,
                        response.bodyAsString()
                    )
                )
            );
        };
    }

    private static byte[] decodePayload(HttpResponse<Buffer> response, String secretName) {
        JsonObject body = response.bodyAsJsonObject();
        JsonObject payload = body == null ? null : body.getJsonObject("payload");
        String data = payload == null ? null : payload.getString("data");
        if (data == null) {
            throw new SecretManagerException("GCP Secret Manager response for secret '%s' contained no payload data".formatted(secretName));
        }
        try {
            return Base64.getDecoder().decode(data);
        } catch (IllegalArgumentException e) {
            throw new SecretManagerException("GCP Secret Manager returned a payload for '%s' that is not base64".formatted(secretName), e);
        }
    }

    private static Throwable wrap(String secretName, String version, Throwable error) {
        if (error instanceof SecretManagerException) {
            return error;
        }
        return new SecretManagerException(
            "Failed to read GCP secret '%s' (version %s): %s".formatted(secretName, version, error.getMessage()),
            error
        );
    }
}
