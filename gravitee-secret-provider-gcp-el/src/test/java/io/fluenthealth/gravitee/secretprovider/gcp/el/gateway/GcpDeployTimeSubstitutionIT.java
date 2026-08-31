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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

/**
 * The two load-bearing measurements for deploy-time secret substitution, against a real gateway with
 * a real deployed API.
 *
 * <ol>
 *   <li><b>Rotation with no gateway restart.</b> The full loop: an API deploys carrying a
 *       {@code secret://gcp/...} reference, the substituted value reaches the upstream, the value
 *       changes, the listener writes it through its retained setter and publishes VALUE_CHANGED,
 *       {@code ApiManagerImpl} fires {@code ReactorEvent.UPDATE} for the cached api, and a later
 *       request carries the <em>new</em> value — with the same gateway process throughout.
 *   <li><b>The {@code /_node/apis/<id>} exposure.</b> Whether the substituted plaintext is readable
 *       from the gateway's own management endpoint. Measured, because it is the main argument against
 *       using this where request-time EL would do.
 * </ol>
 *
 * <p>Secret Manager is stubbed with WireMock rather than pointed at real GCP: the whole point is to
 * flip a value mid-test and observe the consequence, and creating then destroying a real secret
 * version is neither deterministic nor cleanly reversible. The real-GCP path is covered separately by
 * {@code GcpSecretManagerLiveIT}. What is real here is everything gateway-side, which is where the
 * risk lives.
 *
 * <p>{@code GcpGatewayBootstrapIT} deploys no API at all ({@code services.sync.enabled: false}),
 * which is why an earlier attempt to measure any of this there observed nothing.
 */
@Tag("gateway-integration")
class GcpDeployTimeSubstitutionIT {

    private static final Logger log = LoggerFactory.getLogger(GcpDeployTimeSubstitutionIT.class);

    private static final String APIM_VERSION = System.getProperty("apim.version", "4.12.12");
    private static final String API_ID = "deploy-time-e2e";
    private static final String HEADER = "X-Injected-Credential";

    private static final String PROJECT = "example-project";
    private static final String SECRET_NAME = "deploy-time-secret";
    private static final String SECRET_REF = "secret://gcp/" + SECRET_NAME + ":value";
    private static final String VALUE_BEFORE = "secret-value-v1";
    private static final String VALUE_AFTER = "secret-value-v2-rotated";

    private static final String TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/default/token";
    private static final String ACCESS_PATH = "/v1/projects/%s/secrets/%s/versions/latest:access".formatted(PROJECT, SECRET_NAME);

    /** Short enough that a rotation is observable inside a test, long enough not to hammer the stub. */
    private static final int SECRET_TTL_SECONDS = 3;
    private static final int ROTATION_CHECK_SECONDS = 3;

    private static WireMockServer wireMock;
    private static GenericContainer<?> gateway;
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @BeforeAll
    static void startEverything() throws Exception {
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        wireMock.stubFor(get(urlPathEqualTo("/backend")).willReturn(aResponse().withStatus(200).withBody("{\"ok\":true}")));
        wireMock.stubFor(
            get(urlPathEqualTo(TOKEN_PATH)).willReturn(
                aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\"access_token\":\"ya29.stub\",\"expires_in\":3599,\"token_type\":\"Bearer\"}")
            )
        );
        stubSecretValue(VALUE_BEFORE);

        Testcontainers.exposeHostPorts(wireMock.port());
        String host = "http://host.testcontainers.internal:" + wireMock.port();

        Path registry = Files.createTempDirectory("gcp-local-registry");
        Files.writeString(registry.resolve(API_ID + ".json"), LocalRegistryApi.definition(API_ID, host + "/backend", HEADER, SECRET_REF));

        gateway = new GenericContainer<>("graviteeio/apim-gateway:" + APIM_VERSION)
            .withCopyFileToContainer(
                MountableFile.forHostPath(
                    GatewayFixtures.artifact("gravitee-secret-provider-gcp-plugin", "gravitee-secret-provider-gcp-*.zip")
                ),
                "/opt/graviteeio-gateway/plugins/gravitee-secret-provider-gcp.zip"
            )
            .withCopyFileToContainer(
                MountableFile.forHostPath(
                    GatewayFixtures.artifact("gravitee-secret-provider-gcp-el", "gravitee-secret-provider-gcp-el-*.jar")
                ),
                "/opt/graviteeio-gateway/lib/gravitee-secret-provider-gcp-el.jar"
            )
            .withCopyFileToContainer(
                MountableFile.forHostPath(
                    GatewayFixtures.artifact("gravitee-secret-provider-gcp-core", "gravitee-secret-provider-gcp-core-*.jar")
                ),
                "/opt/graviteeio-gateway/lib/gravitee-secret-provider-gcp-core.jar"
            )
            .withCopyFileToContainer(MountableFile.forHostPath(graviteeYml(host)), "/opt/graviteeio-gateway/config/gravitee.yml")
            .withCopyFileToContainer(MountableFile.forHostPath(GatewayFixtures.logbackXml()), "/opt/graviteeio-gateway/config/logback.xml")
            /*
             * Explicit 0755. The gateway runs as uid 1001 (graviteeio) and the image has no
             * /opt/graviteeio-gateway/apis, so Testcontainers creates it — without a mode it lands
             * unreadable by that user and LocalSyncManager dies with AccessDeniedException while the
             * gateway still starts cleanly.
             */
            .withCopyFileToContainer(MountableFile.forHostPath(registry, 0755), "/opt/graviteeio-gateway/apis")
            .withExposedPorts(8082, 18082)
            .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("gateway"))
            .waitingFor(Wait.forLogMessage(".*API Gateway .* started in .*\\n", 1))
            .withStartupTimeout(Duration.ofMinutes(3));
        gateway.start();
    }

    @AfterAll
    static void stopEverything() {
        if (gateway != null) {
            gateway.stop();
        }
        if (wireMock != null) {
            wireMock.stop();
        }
    }

    /** Secret Manager returns the payload base64-encoded under {@code payload.data}. */
    private static void stubSecretValue(String value) {
        wireMock.stubFor(
            get(urlPathEqualTo(ACCESS_PATH)).willReturn(
                aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        "{\"name\":\"%s\",\"payload\":{\"data\":\"%s\"}}".formatted(
                            SECRET_NAME,
                            Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8))
                        )
                    )
            )
        );
    }

    // ── Measurement 1: rotation with no restart ───────────────────────────────

    @Test
    void rotates_the_substituted_value_in_place_without_restarting_the_gateway() throws Exception {
        String processBefore = nodeIdentity();

        // Deploy-time substitution happened before the reactor was built.
        assertThat(gateway.getLogs()).contains("has been deployed");
        assertThat(gateway.getLogs()).as("the listener must have armed and substituted").contains("Substituted a gcp reference at");

        callGateway();
        wireMock.verify(getRequestedFor(urlPathEqualTo("/backend")).withHeader(HEADER, equalTo(VALUE_BEFORE)));

        // Flip the value. The resolver's TTL lapses, the rotation check notices, writes through the
        // retained setter and publishes VALUE_CHANGED.
        stubSecretValue(VALUE_AFTER);

        Awaitility.await()
            .atMost(Duration.ofSeconds(90))
            .pollInterval(Duration.ofSeconds(2))
            .untilAsserted(() -> {
                wireMock.resetRequests();
                callGateway();
                wireMock.verify(getRequestedFor(urlPathEqualTo("/backend")).withHeader(HEADER, equalTo(VALUE_AFTER)));
            });

        assertThat(gateway.getLogs()).as("the gateway must have redeployed the api in place").contains("has been updated");

        // The point of the whole exercise: same process, no restart.
        assertThat(nodeIdentity()).as("gateway must be the same process throughout").isEqualTo(processBefore);
        assertThat(gateway.isRunning()).isTrue();
        assertThat(countOccurrences(gateway.getLogs(), "started in")).as("exactly one startup means no restart").isEqualTo(1);
    }

    // ── Measurement 2: the _node/apis exposure ───────────────────────────────

    @Test
    void reports_whether_the_substituted_plaintext_is_readable_from_node_apis() throws Exception {
        String dump = managementGet("/_node/apis/" + API_ID);

        boolean plaintextVisible = dump.contains(VALUE_BEFORE) || dump.contains(VALUE_AFTER);
        boolean referenceVisible = dump.contains(SECRET_REF);

        log.info("MEASUREMENT _node/apis: plaintextVisible={}, referenceVisible={}", plaintextVisible, referenceVisible);
        log.info("MEASUREMENT _node/apis excerpt: {}", excerptAround(dump, HEADER));

        // Asserted as the current, measured truth rather than a wish. If a future APIM redacts this,
        // the assertion fails and the exposure argument against deploy-time substitution weakens.
        assertThat(plaintextVisible).as("substituted plaintext readable at /_node/apis/<id>: %s", excerptAround(dump, HEADER)).isTrue();
        assertThat(referenceVisible).as("the original secret:// reference should be gone, having been replaced").isFalse();
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static void callGateway() throws Exception {
        HttpResponse<String> response = HTTP.send(
            HttpRequest.newBuilder().uri(URI.create(gatewayUrl())).GET().build(),
            HttpResponse.BodyHandlers.ofString()
        );
        assertThat(response.statusCode()).as("gateway response; body=%s", response.body()).isEqualTo(200);
    }

    /** Node id and start time, from the gateway's own management API — proof of process identity. */
    private static String nodeIdentity() throws Exception {
        return managementGet("/_node");
    }

    private static String managementGet(String path) throws Exception {
        HttpResponse<String> response = HTTP.send(
            HttpRequest.newBuilder()
                .uri(URI.create("http://" + gateway.getHost() + ":" + gateway.getMappedPort(18082) + path))
                .GET()
                .build(),
            HttpResponse.BodyHandlers.ofString()
        );
        assertThat(response.statusCode()).as("management %s; body=%s", path, response.body()).isEqualTo(200);
        return response.body();
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int at = haystack.indexOf(needle);
        while (at >= 0) {
            count++;
            at = haystack.indexOf(needle, at + needle.length());
        }
        return count;
    }

    private static String excerptAround(String text, String anchor) {
        int at = text.indexOf(anchor);
        if (at < 0) {
            return "(anchor '" + anchor + "' not present)";
        }
        return text.substring(Math.max(0, at - 80), Math.min(text.length(), at + 220)).replaceAll("\\s+", " ");
    }

    private static String gatewayUrl() {
        return "http://" + gateway.getHost() + ":" + gateway.getMappedPort(8082) + "/" + API_ID;
    }

    private static Path graviteeYml(String stubHost) throws IOException {
        /*
         * services.sync.local.* is the local registry: LocalApiSynchronizer reads every *.json in the
         * path and registers it through ApiManager. management.type: none keeps the shipped
         * repository-noop plugin, so no MongoDB is needed.
         *
         * services.core.http is ENABLED here, unlike the bootstrap IT, because /_node/apis/<id> is one
         * of the two things this suite exists to measure.
         *
         * el.enabled stays true alongside deployTime.enabled to prove the two mechanisms coexist —
         * request-time EL must not regress.
         */
        String yml = """
            node:
              type: gateway

            management:
              type: none
            ratelimit:
              type: none

            services:
              sync:
                enabled: true
                local:
                  enabled: true
                  path: /opt/graviteeio-gateway/apis
              core:
                http:
                  enabled: true
                  port: 18082
                  host: 0.0.0.0
                  authentication:
                    type: none

            analytics:
              type: none

            secrets:
              gcp:
                enabled: true
                projectId: %s
                baseUrl: %s
                metadataBaseUrl: %s
                secretTtlSeconds: %d
                el:
                  enabled: true
                deployTime:
                  enabled: true
                  rotationCheckSeconds: %d
            """.formatted(PROJECT, stubHost, stubHost, SECRET_TTL_SECONDS, ROTATION_CHECK_SECONDS);
        Path file = Files.createTempDirectory("gcp-deploytime-config").resolve("gravitee.yml");
        Files.writeString(file, yml);
        return file;
    }
}
