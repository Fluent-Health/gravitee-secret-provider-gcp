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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import io.gravitee.secrets.api.errors.SecretManagerException;
import io.reactivex.rxjava3.core.Single;
import io.vertx.rxjava3.core.Vertx;
import io.vertx.rxjava3.ext.web.client.WebClient;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RestGcpSecretManagerClientTest {

    private static final String PROJECT = "example-project";

    private WireMockServer secretManager;
    private Vertx vertx;
    private WebClient webClient;
    private RestGcpSecretManagerClient client;

    @BeforeEach
    void setUp() {
        secretManager = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        secretManager.start();
        vertx = Vertx.vertx();
        webClient = WebClient.create(vertx);
        GcpConfig config = new GcpConfig(
            Map.of("enabled", true, "projectId", PROJECT, "baseUrl", "http://localhost:" + secretManager.port())
        );
        client = new RestGcpSecretManagerClient(webClient, config, () -> Single.just(new GcpAccessToken("ya29.token", Instant.MAX)));
    }

    @AfterEach
    void tearDown() {
        webClient.close();
        vertx.close().blockingAwait();
        secretManager.stop();
    }

    private static String accessPath(String secret, String version) {
        return "/v1/projects/%s/secrets/%s/versions/%s:access".formatted(PROJECT, secret, version);
    }

    private static String base64Payload(String plaintext) {
        return "{\"name\":\"x\",\"payload\":{\"data\":\"%s\"}}".formatted(
            Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test
    void should_access_a_secret_version_and_base64_decode_the_payload() {
        secretManager.stubFor(
            get(urlPathEqualTo(accessPath("db-password", "latest"))).willReturn(
                aResponse().withHeader("Content-Type", "application/json").withBody(base64Payload("hunter2"))
            )
        );

        byte[] payload = client
            .accessSecretVersion("db-password", "latest")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(new String(payload, StandardCharsets.UTF_8)).isEqualTo("hunter2");
    }

    @Test
    void should_send_the_bearer_token() {
        secretManager.stubFor(
            get(urlPathEqualTo(accessPath("db-password", "latest"))).willReturn(
                aResponse().withHeader("Content-Type", "application/json").withBody(base64Payload("hunter2"))
            )
        );

        client.accessSecretVersion("db-password", "latest").test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        secretManager.verify(
            getRequestedFor(urlPathEqualTo(accessPath("db-password", "latest"))).withHeader("Authorization", equalTo("Bearer ya29.token"))
        );
    }

    @Test
    void should_request_an_explicitly_pinned_version_when_asked_for_one() {
        secretManager.stubFor(
            get(urlPathEqualTo(accessPath("db-password", "7"))).willReturn(
                aResponse().withHeader("Content-Type", "application/json").withBody(base64Payload("v7"))
            )
        );

        byte[] payload = client
            .accessSecretVersion("db-password", "7")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(new String(payload, StandardCharsets.UTF_8)).isEqualTo("v7");
    }

    @Test
    void should_url_encode_a_secret_name_so_it_cannot_escape_the_path() {
        secretManager.stubFor(
            get(urlPathEqualTo(accessPath("odd%2Fname", "latest"))).willReturn(
                aResponse().withHeader("Content-Type", "application/json").withBody(base64Payload("ok"))
            )
        );

        client.accessSecretVersion("odd/name", "latest").test().awaitDone(5, TimeUnit.SECONDS).assertComplete();
    }

    @Test
    void should_return_empty_for_a_missing_secret_rather_than_failing() {
        secretManager.stubFor(
            get(urlPathEqualTo(accessPath("nope", "latest"))).willReturn(
                aResponse().withStatus(404).withBody("{\"error\":{\"code\":404,\"message\":\"Secret not found\"}}")
            )
        );

        client.accessSecretVersion("nope", "latest").test().awaitDone(5, TimeUnit.SECONDS).assertComplete().assertNoValues();
    }

    @Test
    void should_name_the_missing_iam_role_when_access_is_denied() {
        secretManager.stubFor(
            get(urlPathEqualTo(accessPath("db-password", "latest"))).willReturn(
                aResponse().withStatus(403).withBody("{\"error\":{\"code\":403,\"message\":\"Permission denied\"}}")
            )
        );

        client
            .accessSecretVersion("db-password", "latest")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertError(SecretManagerException.class)
            .assertError(error -> error.getMessage().contains("roles/secretmanager.secretAccessor"));
    }

    @Test
    void should_fail_on_an_unexpected_status() {
        secretManager.stubFor(get(urlPathEqualTo(accessPath("db-password", "latest"))).willReturn(aResponse().withStatus(503)));

        client
            .accessSecretVersion("db-password", "latest")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertError(SecretManagerException.class)
            .assertError(error -> error.getMessage().contains("503"));
    }

    @Test
    void should_fail_when_the_response_has_no_payload_data() {
        secretManager.stubFor(
            get(urlPathEqualTo(accessPath("db-password", "latest"))).willReturn(
                aResponse().withHeader("Content-Type", "application/json").withBody("{\"name\":\"x\"}")
            )
        );

        client.accessSecretVersion("db-password", "latest").test().awaitDone(5, TimeUnit.SECONDS).assertError(SecretManagerException.class);
    }

    @Test
    void should_propagate_a_token_failure_as_a_secret_manager_exception() {
        RestGcpSecretManagerClient failing = new RestGcpSecretManagerClient(
            webClient,
            new GcpConfig(Map.of("enabled", true, "projectId", PROJECT, "baseUrl", "http://localhost:" + secretManager.port())),
            () -> Single.error(new SecretManagerException("no token for you"))
        );

        failing
            .accessSecretVersion("db-password", "latest")
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertError(SecretManagerException.class)
            .assertError(error -> error.getMessage().contains("no token for you"));
    }
}
