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
 * Resolves a real secret out of a real GCP Secret Manager.
 *
 * <p>This is the test that proves the things only production GCP can: that the REST contract is what
 * we think it is, that the base64 payload decodes, that a {@code secretAccessor} grant is sufficient,
 * and that the payload-as-secret-map convention holds against a real payload. It goes through
 * {@link GcpSecretsElHolder} — the same object the expression language calls — so the code path is
 * the production one, minus the gateway.
 *
 * <h2>Running it</h2>
 *
 * Point it at any secret you own whose payload is a flat JSON object with {@code username} and
 * {@code password} keys, e.g. {@code {"username":"someone","password":"whatever"}}:
 *
 * <pre>
 * gcloud secrets create gravitee-gcp-e2e --replication-policy=automatic
 * printf '{"username":"e2e","password":"synthetic"}' | \
 *   gcloud secrets versions add gravitee-gcp-e2e --data-file=-
 *
 * export GCP_ACCESS_TOKEN=$(gcloud auth print-access-token)
 * export GCP_PROJECT_ID=your-project
 * export GCP_E2E_SECRET_NAME=gravitee-gcp-e2e
 * mvn verify -Pgcloud-integration-test
 * </pre>
 *
 * Assertions are structural rather than exact values, so any secret of that shape works — and no
 * project or secret name is baked into the source.
 *
 * <p>The access token is injected rather than fetched by one of the plugin's own token providers.
 * There is no metadata server outside GCP, and Workload Identity Federation hands CI an
 * {@code external_account} credential, which the service-account-key provider cannot consume. What
 * this test covers is the Secret Manager half; token minting on GKE is covered by
 * {@code MetadataServerTokenProviderTest}.
 */
@Tag("gcloud-integration")
class GcpSecretManagerLiveIT {

    private String secretName;
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
                ("%s is not set. This profile talks to real GCP — see the class comment for the three " +
                    "variables it needs and how to create a suitable secret.").formatted(name)
            );
        }
        return value;
    }

    @BeforeEach
    void setUp() {
        String token = required("GCP_ACCESS_TOKEN", null);
        String projectId = required("GCP_PROJECT_ID", null);
        secretName = required("GCP_E2E_SECRET_NAME", null);

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
    void should_resolve_a_key_out_of_a_real_secret() {
        String value = holder
            .get("/gcp/%s:password".formatted(secretName))
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(value).as("the 'password' key of the secret's flat-JSON payload").isNotBlank();
    }

    /** The same secret, a different key — the flat-JSON-object convention against a real payload. */
    @Test
    void should_resolve_a_second_key_from_the_same_secret() {
        String value = holder
            .get("/gcp/%s".formatted(secretName), "username")
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(value).as("the 'username' key, proving the payload really parsed as a map").isNotBlank();
    }
}
