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
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import io.gravitee.secrets.api.errors.SecretManagerException;
import io.vertx.core.json.JsonObject;
import io.vertx.rxjava3.core.Vertx;
import io.vertx.rxjava3.ext.web.client.WebClient;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ServiceAccountKeyTokenProviderTest {

    private static final Instant NOW = Instant.parse("2026-07-29T12:00:00Z");

    @TempDir
    Path tempDir;

    private WireMockServer tokenEndpoint;
    private Vertx vertx;
    private WebClient webClient;

    @BeforeEach
    void setUp() {
        tokenEndpoint = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        tokenEndpoint.start();
        vertx = Vertx.vertx();
        webClient = WebClient.create(vertx);
    }

    @AfterEach
    void tearDown() {
        webClient.close();
        vertx.close().blockingAwait();
        tokenEndpoint.stop();
    }

    private Path writeKeyFile() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        String pem =
            "-----BEGIN PRIVATE KEY-----\n" +
            Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(keyPair.getPrivate().getEncoded()) +
            "\n-----END PRIVATE KEY-----\n";

        Path keyFile = tempDir.resolve("sa.json");
        Files.writeString(
            keyFile,
            new JsonObject()
                .put("type", "service_account")
                .put("client_email", "apim@fh-apim-dev.iam.gserviceaccount.com")
                .put("private_key", pem)
                .put("token_uri", "http://localhost:" + tokenEndpoint.port() + "/token")
                .encode()
        );
        return keyFile;
    }

    private GcpConfig config(Path keyFile) {
        return new GcpConfig(Map.of("enabled", true, "projectId", "fh-apim-dev", "serviceAccountKeyFile", keyFile.toString()));
    }

    @Test
    void should_exchange_a_signed_jwt_assertion_for_an_access_token() throws Exception {
        Path keyFile = writeKeyFile();
        tokenEndpoint.stubFor(
            post(urlPathEqualTo("/token")).willReturn(
                aResponse().withHeader("Content-Type", "application/json").withBody("{\"access_token\":\"ya29.sa\",\"expires_in\":3599}")
            )
        );

        GcpAccessToken token = new ServiceAccountKeyTokenProvider(webClient, config(keyFile), Clock.fixed(NOW, ZoneOffset.UTC))
            .token()
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete()
            .values()
            .getFirst();

        assertThat(token.value()).isEqualTo("ya29.sa");
        assertThat(token.expiresAt()).isEqualTo(NOW.plusSeconds(3599));
    }

    @Test
    void should_post_the_jwt_bearer_grant_with_a_three_part_assertion() throws Exception {
        Path keyFile = writeKeyFile();
        tokenEndpoint.stubFor(
            post(urlPathEqualTo("/token")).willReturn(
                aResponse().withHeader("Content-Type", "application/json").withBody("{\"access_token\":\"t\",\"expires_in\":60}")
            )
        );

        new ServiceAccountKeyTokenProvider(webClient, config(keyFile), Clock.fixed(NOW, ZoneOffset.UTC))
            .token()
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertComplete();

        String body = tokenEndpoint.getAllServeEvents().getFirst().getRequest().getBodyAsString();
        assertThat(body).contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer");
        String assertion = java.net.URLDecoder.decode(body.split("assertion=")[1], StandardCharsets.UTF_8);
        assertThat(assertion.split("\\.")).hasSize(3);
        String claims = new String(Base64.getUrlDecoder().decode(assertion.split("\\.")[1]), StandardCharsets.UTF_8);
        assertThat(claims).contains("apim@fh-apim-dev.iam.gserviceaccount.com").contains("cloud-platform");
    }

    @Test
    void should_fail_with_a_clear_error_when_the_key_file_is_missing() {
        GcpConfig config = new GcpConfig(
            Map.of("enabled", true, "projectId", "fh-apim-dev", "serviceAccountKeyFile", tempDir.resolve("absent.json").toString())
        );

        assertThatThrownBy(() -> new ServiceAccountKeyTokenProvider(webClient, config, Clock.systemUTC()))
            .isInstanceOf(SecretManagerException.class)
            .hasMessageContaining("service account key file");
    }

    @Test
    void should_fail_when_the_key_file_has_no_private_key() throws IOException {
        Path keyFile = tempDir.resolve("sa.json");
        Files.writeString(keyFile, new JsonObject().put("client_email", "a@b.com").encode());

        assertThatThrownBy(() -> new ServiceAccountKeyTokenProvider(webClient, config(keyFile), Clock.systemUTC()))
            .isInstanceOf(SecretManagerException.class)
            .hasMessageContaining("private_key");
    }
}
