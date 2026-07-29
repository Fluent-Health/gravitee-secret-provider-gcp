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

import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpConfig;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpSecretLocation;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpSecretManagerClient;
import io.fluenthealth.gravitee.secretprovider.gcp.core.SecretPayloadMapper;
import io.gravitee.secrets.api.core.SecretEvent;
import io.gravitee.secrets.api.core.SecretMap;
import io.gravitee.secrets.api.core.SecretURL;
import io.gravitee.secrets.api.plugin.SecretProvider;
import io.reactivex.rxjava3.core.Flowable;
import io.reactivex.rxjava3.core.Maybe;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves {@code secret://gcp/...} references against GCP Secret Manager.
 *
 * @see GcpSecretLocation for the URL forms accepted
 * @see SecretPayloadMapper for how a payload becomes a {@link SecretMap}
 */
public class GcpSecretProvider implements SecretProvider {

    public static final String PLUGIN_ID = "gcp";

    private static final Logger log = LoggerFactory.getLogger(GcpSecretProvider.class);

    private final GcpConfig config;
    private final GcpSecretManagerClient client;
    private final Clock clock;
    private final AutoCloseable resources;
    private final AtomicBoolean watchWarningLogged = new AtomicBoolean();

    public GcpSecretProvider(GcpConfig config, GcpSecretManagerClient client, Clock clock, AutoCloseable resources) {
        this.config = Objects.requireNonNull(config);
        this.client = Objects.requireNonNull(client);
        this.clock = Objects.requireNonNull(clock);
        this.resources = resources;
    }

    @Override
    public Maybe<SecretMap> resolve(SecretURL secretURL) {
        GcpSecretLocation location = GcpSecretLocation.from(secretURL, config);
        return client
            .accessSecretVersion(location.secret(), location.version())
            .map(payload -> SecretPayloadMapper.toSecretMap(payload, secretURL, expiryFor(location)));
    }

    /**
     * Secret versions in GCP are immutable, so an explicitly pinned version can be cached forever;
     * only {@code latest} needs an expiry, and that expiry is the whole rotation mechanism — it is
     * what makes the next read go back to Secret Manager and pick up a new version.
     */
    private Instant expiryFor(GcpSecretLocation location) {
        if (!location.isFloating() || config.secretTtl().isZero()) {
            return null;
        }
        return clock.instant().plus(config.secretTtl());
    }

    /**
     * A logged no-op. GCP Secret Manager has no watch API — versions are immutable and adding one
     * emits no signal a client can subscribe to — so rotation is handled by TTL-driven
     * re-resolution instead. Per the SPI contract this must not signal an error.
     */
    @Override
    public Flowable<SecretEvent> watch(SecretURL secretURL) {
        if (watchWarningLogged.compareAndSet(false, true)) {
            log.info(
                "GCP Secret Manager does not support watching secrets, so watch() on '{}' does nothing. " +
                    "Rotation is picked up by re-resolution after secrets.gcp.secretTtlSeconds ({}s) instead.",
                secretURL.path(),
                config.secretTtl().toSeconds()
            );
        }
        return Flowable.empty();
    }

    @Override
    public GcpSecretProvider stop() {
        if (resources != null) {
            try {
                resources.close();
            } catch (Exception e) {
                log.warn("Failed to release GCP secret provider resources cleanly", e);
            }
        }
        return this;
    }
}
