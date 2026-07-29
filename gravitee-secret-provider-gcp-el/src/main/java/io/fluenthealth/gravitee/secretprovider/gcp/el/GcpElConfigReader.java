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

import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpConfig;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.core.env.Environment;

/**
 * Reads the same {@code secrets.gcp.*} block the secret-provider plugin reads, but out of the
 * gateway's Spring {@link Environment}.
 *
 * <p>Sharing the configuration keys is deliberate: modes A1 and A2 talk to the same project with the
 * same credentials and the same TTL, so having to configure them twice would be a way to get them
 * out of step.
 */
final class GcpElConfigReader {

    private static final String PREFIX = "secrets.gcp.";

    /**
     * Enumerated rather than discovered by prefix scan, which would need {@code EnvironmentUtils}
     * from gravitee-common and a cast to {@code ConfigurableEnvironment}. Keep in step with
     * {@link GcpConfig}.
     */
    private static final List<String> KEYS = List.of(
        "enabled",
        "projectId",
        "defaultVersion",
        "connectTimeoutMs",
        "requestTimeoutMs",
        "serviceAccountKeyFile",
        "secretTtlSeconds",
        "baseUrl",
        "metadataBaseUrl"
    );

    private GcpElConfigReader() {}

    static GcpConfig read(Environment environment) {
        Map<String, Object> conf = new LinkedHashMap<>();
        for (String key : KEYS) {
            String value = environment.getProperty(PREFIX + key);
            if (value != null) {
                conf.put(key, value);
            }
        }
        return new GcpConfig(conf);
    }
}
