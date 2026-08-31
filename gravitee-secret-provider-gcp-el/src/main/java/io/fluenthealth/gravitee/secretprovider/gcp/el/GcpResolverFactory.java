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
package io.fluenthealth.gravitee.secretprovider.gcp.el;

import io.fluenthealth.gravitee.secretprovider.gcp.core.CachingAccessTokenProvider;
import io.fluenthealth.gravitee.secretprovider.gcp.core.CachingGcpSecretResolver;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpAccessTokenProvider;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpConfig;
import io.fluenthealth.gravitee.secretprovider.gcp.core.MetadataServerTokenProvider;
import io.fluenthealth.gravitee.secretprovider.gcp.core.RestGcpSecretManagerClient;
import io.fluenthealth.gravitee.secretprovider.gcp.core.ServiceAccountKeyTokenProvider;
import io.vertx.core.VertxOptions;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.rxjava3.core.Vertx;
import io.vertx.rxjava3.ext.web.client.WebClient;
import java.time.Clock;

/**
 * Builds a {@link CachingGcpSecretResolver} and the Vert.x machinery behind it.
 *
 * <p>Extracted so the EL shim and the deploy-time substitution spike construct their resolvers
 * identically — same token provider selection, same caching, same TTL — rather than drifting apart.
 * Each caller owns the {@link Resolver#close()} lifecycle of what it creates.
 */
final class GcpResolverFactory {

    private GcpResolverFactory() {}

    /** A resolver together with the Vert.x resources it borrows, so the caller can release them. */
    record Resolver(CachingGcpSecretResolver resolver, Vertx vertx, WebClient webClient) {
        void close() {
            if (webClient != null) {
                webClient.close();
            }
            if (vertx != null) {
                vertx.close().blockingAwait();
            }
        }
    }

    static Resolver create(GcpConfig config, String userAgent) {
        Clock clock = Clock.systemUTC();
        Vertx vertx = Vertx.vertx(new VertxOptions().setEventLoopPoolSize(1).setWorkerPoolSize(1));
        WebClient webClient = WebClient.create(
            vertx,
            new WebClientOptions().setConnectTimeout(config.connectTimeoutMs()).setUserAgent(userAgent)
        );
        GcpAccessTokenProvider tokenProvider = new CachingAccessTokenProvider(
            config.usesMetadataServer()
                ? new MetadataServerTokenProvider(webClient, config, clock)
                : new ServiceAccountKeyTokenProvider(webClient, config, clock),
            clock
        );
        CachingGcpSecretResolver resolver = new CachingGcpSecretResolver(
            new RestGcpSecretManagerClient(webClient, config, tokenProvider),
            config,
            clock
        );
        return new Resolver(resolver, vertx, webClient);
    }
}
