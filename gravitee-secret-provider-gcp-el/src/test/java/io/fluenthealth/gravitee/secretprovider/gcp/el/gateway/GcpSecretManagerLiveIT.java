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
package io.fluenthealth.gravitee.secretprovider.gcp.el.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.fluenthealth.gravitee.secretprovider.gcp.core.CachingGcpSecretResolver;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpAccessToken;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpConfig;
import io.fluenthealth.gravitee.secretprovider.gcp.core.RestGcpSecretManagerClient;
import io.fluenthealth.gravitee.secretprovider.gcp.el.GcpSecretsElHolder;
import io.reactivex.rxjava3.core.Single;
import io.vertx.rxjava3.core.Vertx;
import io.vertx.rxjava3.ext.web.client.WebClient;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Resolves the real end-to-end secret out of the real GCP Secret Manager.
 *
 * <p>This is the test that proves the things only production GCP can: that the REST contract is what
 * we think it is, that the base64 payload decodes, that the IAM binding Terraform creates is
 * sufficient, and that the payload-as-secret-map convention lines up with the value Terraform writes.
 * It goes through {@link GcpSecretsElHolder} — the same object the expression language calls — so the
 * code path is the production one, minus the gateway.
 *
 * <p>The secret and the IAM binding are owned by
 * {@code components/pipelines/gravitee-secret-provider-gcp} in Fluent-Health/infra. Its value is
 * synthetic, which is why asserting it here in the clear is fine.
 *
 * <p>The access token is injected rather than fetched by one of the plugin's own token providers.
 * There is no metadata server outside GCP, and Workload Identity Federation hands CI an
 * {@code external_account} credential, which the service-account-key provider cannot consume. What
 * this test covers is the Secret Manager half; token minting on GKE is covered by
 * {@code MetadataServerTokenProviderTest}.
 *
 * <p>Run with {@code mvn verify -Pgcloud-integration-test}, having exported a token:
 *
 * <pre>
 * export GCP_ACCESS_TOKEN=$(gcloud auth print-access-token)
 * </pre>
 *
 * In CI the token comes from {@code google-github-actions/auth} with
 * {@code token_format: access_token}.
 */
@Tag("gcloud-integration")
class GcpSecretManagerLiveIT {

    /** Created by Terraform; see the class comment. */
    private static final String SECRET_NAME = "apim-gcp-secret-provider-e2e-password";

    private static final String EXPECTED_PASSWORD = "e2e-synthetic-not-a-real-secret";
    private static final String EXPECTED_USERNAME = "e2e-user";

    private Vertx vertx;
    private WebClient webClient;
    private GcpSecretsElHolder holder;

    private static String required(String name, String defaultValue) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            if (defaultValue != null) {
                return defaultValue;
            }
            throw new IllegalStateException(
                ("%s is not set. This profile talks to real GCP; export a token first:\n" +
                    "  export GCP_ACCESS_TOKEN=$(gcloud auth print-access-token)").formatted(name)
            );
        }
        return value;
    }

    @BeforeEach
    void setUp() {
        String token = required("GCP_ACCESS_TOKEN", null);
        String projectId = required("GCP_PROJECT_ID", "fh-dev-svc");

        vertx = Vertx.vertx();
        webClient = WebClient.create(vertx);
        GcpConfig config = new GcpConfig(Map.of("enabled", true, "projectId", projectId, "secretTtlSeconds", 300));
        holder = new GcpSecretsElHolder(
            new CachingGcpSecretResolver(
                new RestGcpSecretManagerClient(webClient, config, () -> Single.just(new GcpAccessToken(token, Instant.MAX))),
                config,
                Clock.systemUTC()
            )
        );
    }

    @AfterEach
    void tearDown() {
        if (webClient != null) {
            webClient.close();
        }
        if (vertx != null) {
            vertx.close().blockingAwait();
        }
    }

    @Test
    void should_resolve_a_key_out_of_the_real_secret() {
        String value = holder
            .get("/gcp/%s:password".formatted(SECRET_NAME))
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(value).isEqualTo(EXPECTED_PASSWORD);
    }

    /** The same secret, a different key — the flat-JSON-object convention against a real payload. */
    @Test
    void should_resolve_a_second_key_from_the_same_secret() {
        String value = holder
            .get("/gcp/%s".formatted(SECRET_NAME), "username")
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(value).isEqualTo(EXPECTED_USERNAME);
    }
}
