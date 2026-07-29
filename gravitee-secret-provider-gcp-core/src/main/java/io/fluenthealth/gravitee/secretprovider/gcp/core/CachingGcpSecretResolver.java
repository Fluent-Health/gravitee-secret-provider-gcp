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

import io.gravitee.secrets.api.core.Secret;
import io.gravitee.secrets.api.core.SecretMap;
import io.gravitee.secrets.api.core.SecretURL;
import io.gravitee.secrets.api.errors.SecretManagerException;
import io.reactivex.rxjava3.core.Single;
import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Resolves secrets for request-time use, holding each one until its TTL lapses.
 *
 * <p>This deliberately does <em>not</em> go through {@code GraviteeConfigurationSecretResolver}.
 * That resolver is the right thing for {@code gravitee.yml} references, but it memoises every
 * {@link SecretMap} in a plain map keyed by path and never evicts — it has no notion of the expiry
 * the SPI carries. Delegating to it would make {@code secrets.gcp.secretTtlSeconds} meaningless and
 * a rotation invisible until the gateway restarted, which is one of the things this plugin is for.
 *
 * <p>Caching here is a latency and quota measure, not a correctness one: resolution is reactive all
 * the way down, so a miss is an ordinary asynchronous fetch rather than a blocking call.
 */
public class CachingGcpSecretResolver {

    private final GcpSecretManagerClient client;
    private final GcpConfig config;
    private final Clock clock;
    private final ConcurrentMap<GcpSecretLocation, SecretMap> cache = new ConcurrentHashMap<>();

    public CachingGcpSecretResolver(GcpSecretManagerClient client, GcpConfig config, Clock clock) {
        this.client = Objects.requireNonNull(client);
        this.config = Objects.requireNonNull(config);
        this.clock = Objects.requireNonNull(clock);
    }

    /**
     * Resolves the single secret value a URL points at.
     *
     * @param secretURL a URL whose {@link SecretURL#key()} names the value wanted
     * @return the value, or an error if the secret, the version or the key does not exist
     */
    public Single<String> resolveKey(SecretURL secretURL) {
        GcpSecretLocation location = GcpSecretLocation.from(secretURL, config);
        SecretMap cached = cache.get(location);
        if (cached != null && !cached.isExpired()) {
            return Single.fromCallable(() -> requireKey(cached, secretURL));
        }
        return resolve(location, secretURL).map(secretMap -> requireKey(secretMap, secretURL));
    }

    private Single<SecretMap> resolve(GcpSecretLocation location, SecretURL secretURL) {
        return client
            .accessSecretVersion(location.secret(), location.version())
            .map(payload -> SecretPayloadMapper.toSecretMap(payload, secretURL, expiryFor(location)))
            .switchIfEmpty(
                Single.error(() ->
                    new SecretManagerException(
                        "GCP secret '%s' (version %s) does not exist in project '%s'".formatted(
                            location.secret(),
                            location.version(),
                            config.projectId()
                        )
                    )
                )
            )
            /*
             * Concurrent misses each fetch and the last writer wins, as with access tokens. Sharing
             * one in-flight Single per key would avoid the duplicate calls but means reasoning about
             * a shared subscription whose first subscriber may cancel; at one fetch per TTL per
             * secret the duplication is not worth that.
             */
            .doOnSuccess(secretMap -> cache.put(location, secretMap));
    }

    private java.time.Instant expiryFor(GcpSecretLocation location) {
        if (!location.isFloating() || config.secretTtl().isZero()) {
            return null;
        }
        return clock.instant().plus(config.secretTtl());
    }

    private static String requireKey(SecretMap secretMap, SecretURL secretURL) {
        Optional<Secret> secret = secretURL.isKeyEmpty()
            ? Optional.ofNullable(secretMap.asMap().get(SecretPayloadMapper.DEFAULT_KEY))
            : secretMap.getSecret(secretURL);
        return secret
            .map(Secret::asString)
            .orElseThrow(() ->
                new SecretManagerException(
                    "GCP secret '%s' has no key '%s' (available keys: %s)".formatted(
                        secretURL.path(),
                        secretURL.isKeyEmpty() ? SecretPayloadMapper.DEFAULT_KEY : secretURL.key(),
                        secretMap.asMap().keySet()
                    )
                )
            );
    }

    /** Drops everything cached; the next resolution goes back to Secret Manager. */
    public void invalidateAll() {
        cache.clear();
    }
}
