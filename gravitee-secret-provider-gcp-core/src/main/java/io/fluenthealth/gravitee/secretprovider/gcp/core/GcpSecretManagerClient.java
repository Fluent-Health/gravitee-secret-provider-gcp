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

import io.gravitee.secrets.api.errors.SecretManagerException;
import io.reactivex.rxjava3.core.Maybe;

/** Reads secret payloads out of GCP Secret Manager. */
public interface GcpSecretManagerClient {
    /**
     * Accesses one version of one secret.
     *
     * @param secretName the secret's short name within the configured project
     * @param version a version number, or {@code latest}
     * @return the decoded payload, or {@link Maybe#empty()} if the secret or version does not exist
     * @throws SecretManagerException signalled through the {@link Maybe} for permission and network
     *     failures — that is, for everything that is a misconfiguration rather than an absence
     */
    Maybe<byte[]> accessSecretVersion(String secretName, String version);
}
