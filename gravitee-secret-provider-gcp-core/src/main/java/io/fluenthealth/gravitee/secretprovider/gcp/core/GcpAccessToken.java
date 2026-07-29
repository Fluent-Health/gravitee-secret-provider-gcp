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

import java.time.Duration;
import java.time.Instant;

/**
 * An OAuth2 access token for the Secret Manager API, with the expiry the issuer reported.
 *
 * @param value the bearer token
 * @param expiresAt when the token stops being accepted
 */
public record GcpAccessToken(String value, Instant expiresAt) {
    /**
     * Whether the token can still be used at {@code now}, treating anything inside
     * {@code renewalSkew} of the expiry as already expired. The skew matters because the token
     * travels to Google after we check it, and a token that expires in flight surfaces as a
     * confusing 401 rather than as a refresh.
     */
    public boolean isUsableAt(Instant now, Duration renewalSkew) {
        return now.plus(renewalSkew).isBefore(expiresAt);
    }
}
