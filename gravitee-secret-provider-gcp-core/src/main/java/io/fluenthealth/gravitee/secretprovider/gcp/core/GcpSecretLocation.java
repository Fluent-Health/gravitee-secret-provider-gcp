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

import io.gravitee.secrets.api.core.SecretURL;
import java.util.List;

/**
 * Where a secret lives in GCP Secret Manager, as named by a Gravitee secret URL.
 *
 * <p>The supported spellings mirror GCP's own {@code projects/P/secrets/S/versions/V} ordering:
 *
 * <ul>
 *   <li>{@code secret://gcp/my-secret:key} — the version from {@code secrets.gcp.defaultVersion}
 *   <li>{@code secret://gcp/my-secret/3:key} — version 3, pinned
 *   <li>{@code secret://gcp/my-secret:key?version=3} — equivalent, and the form to use when the
 *       version has to be set independently of the path
 * </ul>
 *
 * <p>The project always comes from configuration, never from the URL: an API definition must not be
 * able to reach into another project.
 *
 * @param secret the secret's short name
 * @param version a version number, or {@code latest}
 */
public record GcpSecretLocation(String secret, String version) {
    /** Query parameter that pins a version without changing the path. */
    public static final String VERSION_QUERY_PARAM = "version";

    public static GcpSecretLocation from(SecretURL secretURL, GcpConfig config) {
        List<String> segments = List.of(secretURL.path().split("/"));
        if (segments.size() > 2) {
            throw new IllegalArgumentException(
                ("Secret URL path '%s' is not a GCP secret location. Expected '<secret>' or '<secret>/<version>' — " +
                    "the project comes from `secrets.gcp.projectId`, not from the URL.").formatted(secretURL.path())
            );
        }
        String versionFromQuery = secretURL.query().get(VERSION_QUERY_PARAM).stream().findFirst().orElse(null);
        String versionFromPath = segments.size() == 2 ? segments.get(1) : null;
        String version = firstNonBlank(versionFromQuery, versionFromPath, config.defaultVersion());
        return new GcpSecretLocation(segments.getFirst(), version);
    }

    private static String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate.trim();
            }
        }
        return GcpConfig.LATEST_VERSION;
    }

    /** True when this resolves whatever version is current, and so can observe a rotation. */
    public boolean isFloating() {
        return GcpConfig.LATEST_VERSION.equalsIgnoreCase(version);
    }
}
