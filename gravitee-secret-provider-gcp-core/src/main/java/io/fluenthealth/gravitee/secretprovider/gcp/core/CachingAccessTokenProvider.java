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

import io.reactivex.rxjava3.core.Single;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Holds an access token until it is close to expiring, so reading a secret does not also mean a
 * round trip to the metadata server.
 */
public class CachingAccessTokenProvider implements GcpAccessTokenProvider {

    /** A token with less than this left on it is refreshed rather than used. */
    public static final Duration RENEWAL_SKEW = Duration.ofSeconds(60);

    private final GcpAccessTokenProvider delegate;
    private final Clock clock;
    private final AtomicReference<GcpAccessToken> cached = new AtomicReference<>();

    public CachingAccessTokenProvider(GcpAccessTokenProvider delegate, Clock clock) {
        this.delegate = Objects.requireNonNull(delegate);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public Single<GcpAccessToken> token() {
        return Single.defer(() -> {
            GcpAccessToken current = cached.get();
            if (current != null && current.isUsableAt(clock.instant(), RENEWAL_SKEW)) {
                return Single.just(current);
            }
            /*
             * Concurrent callers arriving on a miss will each fetch, and the last one to complete
             * wins the cache slot. That is deliberate: tokens are valid for an hour, so a miss
             * happens roughly hourly, and every racing caller gets a usable token. De-duplicating
             * would mean sharing a subscription across callers and having to reason about what
             * happens to the shared Single when the first subscriber unsubscribes.
             */
            return delegate.token().doOnSuccess(cached::set);
        });
    }
}
