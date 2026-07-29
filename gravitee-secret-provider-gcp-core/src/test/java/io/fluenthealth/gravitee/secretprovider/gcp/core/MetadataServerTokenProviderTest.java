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
import io.vertx.rxjava3.core.Vertx;
import io.vertx.rxjava3.ext.web.client.WebClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MetadataServerTokenProviderTest {

    private static final String TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/default/token";
    private static final Instant NOW = Instant.parse("2026-07-29T12:00:00Z");

    private WireMockServer metadataServer;
    private Vertx vertx;
    private WebClient webClient;

    @BeforeEach
    void setUp() {
        metadataServer = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        metadataServer.start();
        vertx = Vertx.vertx();
        webClient = WebClient.create(vertx);
    }

    @AfterEach
    void tearDown() {
        webClient.close();
        vertx.close().blockingAwait();
        metadataServer.stop();
    }

    private GcpConfig config() {
        return new GcpConfig(
            Map.of("enabled", true, "projectId", "fh-apim-test", "metadataBaseUrl", "http://localhost:" + metadataServer.port())
        );
    }

    private MetadataServerTokenProvider provider() {
        return new MetadataServerTokenProvider(webClient, config(), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void should_fetch_a_token_and_derive_its_expiry_from_expires_in() {
        metadataServer.stubFor(
            get(urlPathEqualTo(TOKEN_PATH)).willReturn(
                aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\"access_token\":\"ya29.a0token\",\"expires_in\":3599,\"token_type\":\"Bearer\"}")
            )
        );

        GcpAccessToken token = provider().token().test().awaitDone(5, TimeUnit.SECONDS).assertComplete().values().getFirst();

        assertThat(token.value()).isEqualTo("ya29.a0token");
        assertThat(token.expiresAt()).isEqualTo(NOW.plusSeconds(3599));
    }

    @Test
    void should_send_the_metadata_flavor_header_because_the_metadata_server_rejects_requests_without_it() {
        metadataServer.stubFor(
            get(urlPathEqualTo(TOKEN_PATH)).willReturn(
                aResponse().withHeader("Content-Type", "application/json").withBody("{\"access_token\":\"t\",\"expires_in\":60}")
            )
        );

        provider().token().test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        metadataServer.verify(getRequestedFor(urlPathEqualTo(TOKEN_PATH)).withHeader("Metadata-Flavor", equalTo("Google")));
    }

    @Test
    void should_report_an_actionable_error_when_the_metadata_server_is_unreachable() {
        // Build against the live port first: stopping WireMock makes port() throw.
        MetadataServerTokenProvider provider = provider();
        metadataServer.stop();

        provider
            .token()
            .test()
            .awaitDone(10, TimeUnit.SECONDS)
            .assertError(SecretManagerException.class)
            .assertError(error -> error.getMessage().contains("Workload Identity"));
    }

    @Test
    void should_fail_when_the_metadata_server_returns_an_error_status() {
        metadataServer.stubFor(get(urlPathEqualTo(TOKEN_PATH)).willReturn(aResponse().withStatus(500).withBody("boom")));

        provider()
            .token()
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertError(SecretManagerException.class)
            .assertError(error -> error.getMessage().contains("500"));
    }

    @Test
    void should_fail_when_the_response_carries_no_access_token() {
        metadataServer.stubFor(
            get(urlPathEqualTo(TOKEN_PATH)).willReturn(
                aResponse().withHeader("Content-Type", "application/json").withBody("{\"expires_in\":60}")
            )
        );

        provider().token().test().awaitDone(5, TimeUnit.SECONDS).assertError(SecretManagerException.class);
    }

    @Test
    void should_reuse_a_cached_token_rather_than_calling_the_metadata_server_on_every_secret_read() {
        metadataServer.stubFor(
            get(urlPathEqualTo(TOKEN_PATH)).willReturn(
                aResponse().withHeader("Content-Type", "application/json").withBody("{\"access_token\":\"t1\",\"expires_in\":3599}")
            )
        );
        GcpAccessTokenProvider caching = new CachingAccessTokenProvider(provider(), Clock.fixed(NOW, ZoneOffset.UTC));

        caching.token().test().awaitDone(5, TimeUnit.SECONDS).assertComplete();
        caching.token().test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        assertThat(metadataServer.getAllServeEvents()).hasSize(1);
    }

    @Test
    void should_refresh_a_token_that_is_inside_the_expiry_skew() {
        metadataServer.stubFor(
            get(urlPathEqualTo(TOKEN_PATH)).willReturn(
                aResponse().withHeader("Content-Type", "application/json").withBody("{\"access_token\":\"t1\",\"expires_in\":30}")
            )
        );
        // 30s of validity is inside the 60s renewal skew, so the token is never considered usable.
        GcpAccessTokenProvider caching = new CachingAccessTokenProvider(provider(), Clock.fixed(NOW, ZoneOffset.UTC));

        caching.token().test().awaitDone(5, TimeUnit.SECONDS).assertComplete();
        caching.token().test().awaitDone(5, TimeUnit.SECONDS).assertComplete();

        assertThat(metadataServer.getAllServeEvents()).hasSize(2);
    }

    @Test
    void should_consider_a_token_usable_only_outside_the_renewal_skew() {
        GcpAccessToken token = new GcpAccessToken("t", NOW.plusSeconds(120));

        assertThat(token.isUsableAt(NOW, Duration.ofSeconds(60))).isTrue();
        assertThat(token.isUsableAt(NOW.plusSeconds(61), Duration.ofSeconds(60))).isFalse();
    }
}
