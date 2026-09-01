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
import org.testcontainers.containers.Container;
import org.testcontainers.containers.ExecConfig;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

/**
 * What a real gateway's REVOKE events do to retained substitutions.
 *
 * <p>The spike this grew out of measured rotation and the {@code /_node/apis} exposure but never
 * published a REVOKE — VALUE_CHANGED does not, and it deployed only one revision. That left the
 * riskiest part of the design unproven, because both ways of getting it wrong are silent:
 *
 * <ol>
 *   <li>{@code ApiManagerImpl.update(api)} publishes DISCOVER for the new revision and <em>then</em>
 *       REVOKE for the previous one. A handler that releases on any REVOKE for the api's id drops the
 *       entry the live revision needs, and rotation is dead from the first redeploy onwards.
 *   <li>{@code undeploy(apiId)} publishes REVOKE for the revision in force. A handler that keeps it
 *       goes on resolving, rewriting and republishing a definition the gateway no longer serves.
 * </ol>
 *
 * <p>Both are driven here, in order, against {@code graviteeio/apim-gateway}, and both are asserted
 * <em>behaviourally</em> — by whether a later value change reaches the API the gateway is actually
 * serving — with the handler's own log lines as corroboration rather than as the whole proof.
 *
 * <p>A second API, {@code deploy-time-control}, is deployed and never touched. It is the positive
 * control for the last assertion: "the revoked API published no further VALUE_CHANGED" is only
 * evidence if something proves the rotation thread ran and noticed the flip at all, and the control
 * API rotating is that something.
 *
 * <p>{@code GcpDeployTimeSubstitutionIT} covers the rotation and exposure measurements and boots its
 * own gateway; this suite deliberately does not share one, so that a failure here points at
 * revocation rather than at test ordering.
 */
@Tag("gateway-integration")
class GcpDeployTimeRevocationIT {

    private static final Logger log = LoggerFactory.getLogger(GcpDeployTimeRevocationIT.class);

    private static final String APIM_VERSION = System.getProperty("apim.version", "4.12.12");

    /** The API whose revisions are churned. */
    private static final String API_ID = "deploy-time-revoke";

    /** Deployed once and left alone, so a rotation that reaches nothing can be told from one that ran. */
    private static final String CONTROL_API_ID = "deploy-time-control";

    private static final String HEADER = "X-Injected-Credential";

    private static final String PROJECT = "example-project";
    private static final String SECRET_NAME = "deploy-time-secret";
    private static final String SECRET_REF = "secret://gcp/" + SECRET_NAME + ":value";
    private static final String VALUE_1 = "secret-value-v1";
    private static final String VALUE_2 = "secret-value-v2";
    private static final String VALUE_3 = "secret-value-v3";

    private static final String TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/default/token";
    private static final String ACCESS_PATH = "/v1/projects/%s/secrets/%s/versions/latest:access".formatted(PROJECT, SECRET_NAME);

    /** Short enough that three rotations fit in a test, long enough not to hammer the stub. */
    private static final int SECRET_TTL_SECONDS = 3;
    private static final int ROTATION_CHECK_SECONDS = 3;

    /**
     * The local registry's watcher polls every 5s, so anything driven through a dropped file needs
     * headroom well past that on a loaded CI runner.
     */
    private static final Duration PATIENCE = Duration.ofSeconds(120);

    private static WireMockServer wireMock;
    private static GenericContainer<?> gateway;
    private static String stubHost;
    private static long deployedAtBase;

    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @BeforeAll
    static void startEverything() throws Exception {
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        wireMock.stubFor(get(urlPathEqualTo("/backend")).willReturn(aResponse().withStatus(200).withBody("{\"ok\":true}")));
        wireMock.stubFor(get(urlPathEqualTo("/control-backend")).willReturn(aResponse().withStatus(200).withBody("{\"ok\":true}")));
        wireMock.stubFor(
            get(urlPathEqualTo(TOKEN_PATH)).willReturn(
                aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\"access_token\":\"ya29.stub\",\"expires_in\":3599,\"token_type\":\"Bearer\"}")
            )
        );
        stubSecretValue(VALUE_1);

        Testcontainers.exposeHostPorts(wireMock.port());
        stubHost = "http://host.testcontainers.internal:" + wireMock.port();
        deployedAtBase = System.currentTimeMillis();

        Path registry = Files.createTempDirectory("gcp-local-registry-revoke");
        Files.writeString(registry.resolve(API_ID + "-1.json"), LocalRegistryApi.definition(revision("1", 0)));
        Files.writeString(
            registry.resolve(CONTROL_API_ID + ".json"),
            LocalRegistryApi.definition(
                new LocalRegistryApi.Revision(CONTROL_API_ID, stubHost + "/control-backend", HEADER, SECRET_REF, "1", deployedAtBase, true)
            )
        );

        gateway = GatewayFixtures.gatewayWith(APIM_VERSION, graviteeYml(stubHost), registry, log);
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

    /**
     * The whole lifecycle as one ordered method. Splitting it into three would make each depend on the
     * previous one having run, which JUnit does not promise and which reads as three independent
     * measurements when it is one sequence.
     */
    @Test
    void keeps_the_live_revisions_substitutions_across_a_redeploy_and_releases_them_on_undeploy() throws Exception {
        // ── Revision 1 deployed and substituted ──────────────────────────────
        awaitLog("Retained 1 substitution(s) for " + definitionOf(API_ID) + " revision 1");
        awaitLog("Retained 1 substitution(s) for " + definitionOf(CONTROL_API_ID) + " revision 1");
        assertUpstreamReceives("/backend", API_ID, VALUE_1);

        // ── A second revision: its DISCOVER precedes revision 1's REVOKE ─────
        dropIntoRegistry(API_ID + "-2.json", LocalRegistryApi.definition(revision("2", 60_000)));

        awaitLog("Retained 1 substitution(s) for " + definitionOf(API_ID) + " revision 2");
        awaitLog("Ignoring REVOKE of " + definitionOf(API_ID) + " revision 1; it is superseded by the retained revision 2");
        assertThat(gateway.getLogs())
            .as("revision 1's REVOKE must not have released anything")
            .doesNotContain("Released 1 retained substitution(s) for " + definitionOf(API_ID) + " revision 1");

        /*
         * The assertion that can actually fail. If the superseded revision's REVOKE had released the
         * entry, no rotation would ever reach revision 2 again and this would time out on VALUE_1.
         */
        stubSecretValue(VALUE_2);
        awaitUpstreamReceives("/backend", API_ID, VALUE_2);
        assertThat(publishCountFor(API_ID)).isEqualTo(1);

        // ── Undeploy: REVOKE for the revision actually in force ──────────────
        dropIntoRegistry(API_ID + "-3.json", LocalRegistryApi.definition(revision("3", 120_000).stopped()));

        awaitLog("Released 1 retained substitution(s) for " + definitionOf(API_ID) + " revision 2");
        Awaitility.await("the api stops being served")
            .atMost(PATIENCE)
            .pollInterval(Duration.ofSeconds(2))
            .untilAsserted(() -> assertThat(statusOf(API_ID)).isEqualTo(404));

        /*
         * Nothing more may be published for the revoked api. The control api rotating to VALUE_3 is
         * what makes that a measurement rather than an absence: it proves the rotation thread ran,
         * re-resolved, and saw the new value.
         */
        stubSecretValue(VALUE_3);
        awaitUpstreamReceives("/control-backend", CONTROL_API_ID, VALUE_3);
        assertThat(publishCountFor(CONTROL_API_ID)).as("control api: one publish per flip, three flips minus the first").isEqualTo(2);
        assertThat(publishCountFor(API_ID)).as("the revoked api must be left alone").isEqualTo(1);
    }

    // ── driving the local registry ────────────────────────────────────────────

    private static LocalRegistryApi.Revision revision(String revision, long createdAtOffsetMs) {
        return new LocalRegistryApi.Revision(
            API_ID,
            stubHost + "/backend",
            HEADER,
            SECRET_REF,
            revision,
            deployedAtBase + createdAtOffsetMs,
            true
        );
    }

    /**
     * Adds one definition file to the running gateway's local registry.
     *
     * <p>Copied to {@code /tmp} and then <em>renamed</em> into place, rather than written into the
     * watched directory. A rename fires ENTRY_CREATE and nothing else; writing in place also fires
     * ENTRY_MODIFY, and {@code LocalApiSynchronizer}'s ENTRY_MODIFY branch casts the stored definition
     * to the V2 api class — a {@code ClassCastException} for a V4 api, thrown inside the watcher's
     * {@code Flowable.interval}, which kills the watcher for the rest of the process. The rename runs
     * as root because the registry directory is root-owned while the gateway runs as uid 1001.
     */
    private static void dropIntoRegistry(String fileName, String definitionJson) throws Exception {
        Path local = Files.createTempDirectory("gcp-registry-drop").resolve(fileName);
        Files.writeString(local, definitionJson);
        gateway.copyFileToContainer(MountableFile.forHostPath(local, 0644), "/tmp/" + fileName);

        Container.ExecResult moved = gateway.execInContainer(
            ExecConfig.builder()
                .user("root")
                .command(new String[] { "mv", "/tmp/" + fileName, GatewayFixtures.LOCAL_REGISTRY_DIR + "/" + fileName })
                .build()
        );
        assertThat(moved.getExitCode()).as("mv into the local registry failed: %s", moved.getStderr()).isZero();
    }

    // ── assertions ────────────────────────────────────────────────────────────

    /**
     * Mirrors {@code Definition}'s record {@code toString}, which is what the handler's log lines
     * carry. Spelled out here so a change to either side shows up as a failed await rather than as a
     * silently unmatched substring.
     */
    private static String definitionOf(String apiId) {
        return "Definition[kind=api-v4, id=" + apiId + "]";
    }

    private static void awaitLog(String expected) {
        Awaitility.await(expected)
            .atMost(PATIENCE)
            .pollInterval(Duration.ofSeconds(1))
            .untilAsserted(() -> assertThat(gateway.getLogs()).contains(expected));
    }

    private static int publishCountFor(String apiId) {
        String line = "Publishing VALUE_CHANGED for " + definitionOf(apiId);
        String logs = gateway.getLogs();
        int count = 0;
        int at = logs.indexOf(line);
        while (at >= 0) {
            count++;
            at = logs.indexOf(line, at + line.length());
        }
        return count;
    }

    private static void assertUpstreamReceives(String upstreamPath, String apiId, String expectedValue) throws Exception {
        wireMock.resetRequests();
        assertThat(statusOf(apiId)).isEqualTo(200);
        wireMock.verify(getRequestedFor(urlPathEqualTo(upstreamPath)).withHeader(HEADER, equalTo(expectedValue)));
    }

    private static void awaitUpstreamReceives(String upstreamPath, String apiId, String expectedValue) {
        Awaitility.await("%s carries %s".formatted(upstreamPath, expectedValue))
            .atMost(PATIENCE)
            .pollInterval(Duration.ofSeconds(2))
            .untilAsserted(() -> assertUpstreamReceives(upstreamPath, apiId, expectedValue));
    }

    private static int statusOf(String apiId) throws Exception {
        HttpResponse<String> response = HTTP.send(
            HttpRequest.newBuilder()
                .uri(URI.create("http://" + gateway.getHost() + ":" + gateway.getMappedPort(8082) + "/" + apiId))
                .GET()
                .build(),
            HttpResponse.BodyHandlers.ofString()
        );
        return response.statusCode();
    }

    // ── fixtures ──────────────────────────────────────────────────────────────

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

    private static Path graviteeYml(String stubHost) throws IOException {
        /*
         * No services.core.http block here, unlike the rotation suite: nothing in this measurement
         * reads /_node, so the shipped default (localhost, basic auth) is left alone.
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
                  path: %s

            analytics:
              type: none

            secrets:
              gcp:
                enabled: true
                projectId: %s
                baseUrl: %s
                metadataBaseUrl: %s
                secretTtlSeconds: %d
                deployTime:
                  enabled: true
                  rotationCheckSeconds: %d
            """.formatted(GatewayFixtures.LOCAL_REGISTRY_DIR, PROJECT, stubHost, stubHost, SECRET_TTL_SECONDS, ROTATION_CHECK_SECONDS);
        Path file = Files.createTempDirectory("gcp-revocation-config").resolve("gravitee.yml");
        Files.writeString(file, yml);
        return file;
    }
}
