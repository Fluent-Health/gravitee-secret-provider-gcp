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
package io.fluenthealth.gravitee.secretprovider.gcp;

import io.fluenthealth.gravitee.secretprovider.gcp.core.CachingAccessTokenProvider;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpAccessTokenProvider;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpConfig;
import io.fluenthealth.gravitee.secretprovider.gcp.core.MetadataServerTokenProvider;
import io.fluenthealth.gravitee.secretprovider.gcp.core.RestGcpSecretManagerClient;
import io.fluenthealth.gravitee.secretprovider.gcp.core.ServiceAccountKeyTokenProvider;
import io.gravitee.secrets.api.plugin.SecretProvider;
import io.gravitee.secrets.api.plugin.SecretProviderFactory;
import io.vertx.core.VertxOptions;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.rxjava3.core.Vertx;
import io.vertx.rxjava3.ext.web.client.WebClient;
import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Entry point named by {@code plugin.properties}.
 *
 * <p>Note there is deliberately no {@code feature=} key in {@code plugin.properties}: that key is
 * what makes the gateway gate a plugin on the licence, and this plugin is OSS.
 */
public class GcpSecretProviderFactory implements SecretProviderFactory<GcpSecretManagerConfiguration> {

    private static final Logger log = LoggerFactory.getLogger(GcpSecretProviderFactory.class);

    @Override
    public SecretProvider create(GcpSecretManagerConfiguration configuration) {
        /*
         * The SPI hands us configuration and nothing else — there is no Vert.x instance to inject —
         * so the provider owns one, as the OSS Kubernetes provider's client does. Pools are sized
         * at 1: this issues one small HTTPS request per secret resolution, and the gateway's own
         * event loops must not be borrowed for it.
         */
        Vertx vertx = Vertx.vertx(new VertxOptions().setEventLoopPoolSize(1).setWorkerPoolSize(1));
        WebClient webClient = WebClient.create(
            vertx,
            new WebClientOptions().setConnectTimeout(configuration.connectTimeoutMs()).setUserAgent("gravitee-secret-provider-gcp")
        );
        Clock clock = Clock.systemUTC();

        GcpAccessTokenProvider tokenProvider = new CachingAccessTokenProvider(
            configuration.usesMetadataServer()
                ? new MetadataServerTokenProvider(webClient, configuration, clock)
                : new ServiceAccountKeyTokenProvider(webClient, configuration, clock),
            clock
        );

        log.info(
            "GCP secret provider '{}' initialised for project '{}' (default version '{}', TTL {}s, auth: {})",
            GcpSecretProvider.PLUGIN_ID,
            configuration.projectId(),
            configuration.defaultVersion(),
            configuration.secretTtl().toSeconds(),
            configuration.usesMetadataServer() ? "Workload Identity via metadata server" : "service account key file"
        );

        return new GcpSecretProvider(configuration, new RestGcpSecretManagerClient(webClient, configuration, tokenProvider), clock, () -> {
            webClient.close();
            vertx.close().blockingAwait();
        });
    }
}
