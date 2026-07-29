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
import io.gravitee.secrets.api.plugin.SecretManagerConfiguration;
import java.util.Map;

/**
 * The plugin's configuration type. Adds nothing to {@link GcpConfig} but its package.
 *
 * <p>This exists because of how the gateway finds a secret-provider plugin's configuration class:
 * {@code SecretManagerConfigurationClassFinder} scans the package of the class named by
 * {@code plugin.properties} for an implementation of {@code SecretManagerConfiguration}. It does not
 * read the factory's generic type parameter. {@link GcpConfig} lives in the core module — shared with
 * the EL shim, which reads the same {@code secrets.gcp.*} block — so it is not in the factory's
 * package and the scan misses it.
 *
 * <p>The failure that causes is worth recognising, because it names the class it could not configure
 * and so reads like the plugin is missing entirely:
 *
 * <pre>
 * ERROR DefaultSecretProviderPluginManager - Unexpected error while loading secret provider plugin:
 *   io.fluenthealth.gravitee.secretprovider.gcp.GcpSecretProviderFactory
 * SecretProviderNotFoundException: No secret-provider plugin found for provider id: 'gcp'
 * </pre>
 *
 * <p>The constructor has to be redeclared: {@code GraviteeConfigurationSecretResolver} instantiates
 * the configuration reflectively via {@code getDeclaredConstructor(Map.class)}, and constructors are
 * not inherited.
 */
public class GcpSecretManagerConfiguration extends GcpConfig implements SecretManagerConfiguration {

    public GcpSecretManagerConfiguration(Map<String, Object> conf) {
        super(conf);
    }
}
