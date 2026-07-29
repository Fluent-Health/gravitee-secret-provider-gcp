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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

class GcpConfigTest {

    @Test
    void should_be_disabled_and_inert_when_enabled_is_absent() {
        GcpConfig config = new GcpConfig(Map.of());

        assertThat(config.isEnabled()).isFalse();
        // Nothing else is read when disabled, so a config with no projectId must not throw.
        assertThat(config.projectId()).isNull();
    }

    @Test
    void should_read_configuration_when_enabled() {
        GcpConfig config = new GcpConfig(
            Map.of(
                "enabled",
                true,
                "projectId",
                "example-project",
                "defaultVersion",
                "3",
                "connectTimeoutMs",
                1_500,
                "requestTimeoutMs",
                4_000,
                "secretTtlSeconds",
                60L
            )
        );

        assertThat(config.isEnabled()).isTrue();
        assertThat(config.projectId()).isEqualTo("example-project");
        assertThat(config.defaultVersion()).isEqualTo("3");
        assertThat(config.connectTimeoutMs()).isEqualTo(1_500);
        assertThat(config.requestTimeoutMs()).isEqualTo(4_000);
        assertThat(config.secretTtl()).isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    void should_coerce_string_values_because_gravitee_yml_properties_arrive_as_strings() {
        GcpConfig config = new GcpConfig(
            Map.of("enabled", "true", "projectId", "example-project", "connectTimeoutMs", "2000", "secretTtlSeconds", "90")
        );

        assertThat(config.isEnabled()).isTrue();
        assertThat(config.connectTimeoutMs()).isEqualTo(2_000);
        assertThat(config.secretTtl()).isEqualTo(Duration.ofSeconds(90));
    }

    @Test
    void should_default_to_latest_version_so_rotation_is_picked_up_without_a_redeploy() {
        GcpConfig config = new GcpConfig(Map.of("enabled", true, "projectId", "example-project"));

        assertThat(config.defaultVersion()).isEqualTo("latest");
        assertThat(config.secretTtl()).isEqualTo(Duration.ofSeconds(300));
        assertThat(config.secretManagerBaseUrl()).isEqualTo("https://secretmanager.googleapis.com");
        assertThat(config.metadataBaseUrl()).isEqualTo("http://metadata.google.internal");
        assertThat(config.serviceAccountKeyFile()).isEmpty();
        assertThat(config.usesMetadataServer()).isTrue();
    }

    @Test
    void should_fail_fast_when_enabled_without_a_project_id() {
        assertThatThrownBy(() -> new GcpConfig(Map.of("enabled", true)))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("secrets.gcp.projectId");
    }

    @Test
    void should_switch_to_service_account_key_when_one_is_configured() {
        GcpConfig config = new GcpConfig(
            Map.of("enabled", true, "projectId", "example-project", "serviceAccountKeyFile", "/etc/gcp/sa.json")
        );

        assertThat(config.serviceAccountKeyFile()).isEqualTo("/etc/gcp/sa.json");
        assertThat(config.usesMetadataServer()).isFalse();
    }
}
