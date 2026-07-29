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
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.rxjava3.ext.web.client.HttpResponse;
import io.vertx.rxjava3.ext.web.client.WebClient;
import java.time.Clock;
import java.util.Objects;

/**
 * Obtains an access token from the GKE/GCE metadata server.
 *
 * <p>This is the production path and needs no static key material: under Workload Identity the
 * node's metadata server mints tokens for the Kubernetes service account bound to a Google service
 * account, so the only thing to provision is the IAM binding.
 *
 * <p>Tokens are <em>not</em> cached here — wrap this in a {@link CachingAccessTokenProvider}.
 */
public class MetadataServerTokenProvider implements GcpAccessTokenProvider {

    /**
     * No {@code scopes} query parameter is sent. Tokens minted for a Workload Identity service
     * account already carry {@code cloud-platform}, and asking for a narrower scope on that path is
     * rejected rather than honoured.
     */
    static final String TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/default/token";

    private static final String METADATA_FLAVOR_HEADER = "Metadata-Flavor";
    private static final String METADATA_FLAVOR_VALUE = "Google";

    private final WebClient webClient;
    private final GcpConfig config;
    private final Clock clock;

    public MetadataServerTokenProvider(WebClient webClient, GcpConfig config, Clock clock) {
        this.webClient = Objects.requireNonNull(webClient);
        this.config = Objects.requireNonNull(config);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public Single<GcpAccessToken> token() {
        String url = config.metadataBaseUrl() + TOKEN_PATH;
        return webClient
            .getAbs(url)
            .putHeader(METADATA_FLAVOR_HEADER, METADATA_FLAVOR_VALUE)
            .timeout(config.requestTimeoutMs())
            .send()
            .map(this::toToken)
            .onErrorResumeNext(error -> Single.error(wrap(url, error)));
    }

    private GcpAccessToken toToken(HttpResponse<Buffer> response) {
        if (response.statusCode() != 200) {
            throw new SecretManagerException(
                "GCP metadata server returned HTTP %d when minting an access token: %s".formatted(
                    response.statusCode(),
                    response.bodyAsString()
                )
            );
        }
        JsonObject body = response.bodyAsJsonObject();
        String accessToken = body == null ? null : body.getString("access_token");
        if (accessToken == null || accessToken.isBlank()) {
            throw new SecretManagerException("GCP metadata server response contained no 'access_token'");
        }
        // `expires_in` is documented as always present; defaulting to 0 rather than failing means a
        // missing value degrades to "refresh on every call", not to a broken gateway.
        long expiresIn = body.getLong("expires_in", 0L);
        return new GcpAccessToken(accessToken, clock.instant().plusSeconds(expiresIn));
    }

    private static Throwable wrap(String url, Throwable error) {
        if (error instanceof SecretManagerException) {
            return error;
        }
        return new SecretManagerException(
            ("Could not reach the GCP metadata server at %s. The gateway must run on GKE/GCE with Workload Identity " +
                "configured, or `secrets.gcp.serviceAccountKeyFile` must be set for local development.").formatted(url),
            error
        );
    }
}
