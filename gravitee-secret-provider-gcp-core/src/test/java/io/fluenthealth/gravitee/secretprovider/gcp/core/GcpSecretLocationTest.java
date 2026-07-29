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

import io.gravitee.secrets.api.core.SecretURL;
import java.util.Map;
import org.junit.jupiter.api.Test;

class GcpSecretLocationTest {

    private static final GcpConfig CONFIG = new GcpConfig(Map.of("enabled", true, "projectId", "fh-apim-test"));

    private static GcpSecretLocation location(String url) {
        return GcpSecretLocation.from(SecretURL.from(url), CONFIG);
    }

    @Test
    void should_default_the_version_so_rotation_is_transparent() {
        GcpSecretLocation location = location("secret://gcp/db-password:password");

        assertThat(location.secret()).isEqualTo("db-password");
        assertThat(location.version()).isEqualTo("latest");
        assertThat(location.isFloating()).isTrue();
    }

    @Test
    void should_read_a_version_pinned_in_the_path() {
        GcpSecretLocation location = location("secret://gcp/db-password/7:password");

        assertThat(location.secret()).isEqualTo("db-password");
        assertThat(location.version()).isEqualTo("7");
        assertThat(location.isFloating()).isFalse();
    }

    @Test
    void should_read_a_version_pinned_in_the_query_string() {
        GcpSecretLocation location = location("secret://gcp/db-password:password?version=9");

        assertThat(location.version()).isEqualTo("9");
    }

    @Test
    void should_prefer_the_query_string_version_over_the_path() {
        GcpSecretLocation location = location("secret://gcp/db-password/7:password?version=9");

        assertThat(location.version()).isEqualTo("9");
    }

    @Test
    void should_honour_a_configured_default_version() {
        GcpConfig pinned = new GcpConfig(Map.of("enabled", true, "projectId", "fh-apim-test", "defaultVersion", "4"));

        GcpSecretLocation location = GcpSecretLocation.from(SecretURL.from("secret://gcp/db-password:password"), pinned);

        assertThat(location.version()).isEqualTo("4");
    }

    @Test
    void should_reject_a_path_that_looks_like_a_full_gcp_resource_name() {
        assertThatThrownBy(() -> location("secret://gcp/projects/other/secrets/x:key"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("secrets.gcp.projectId");
    }

    @Test
    void should_work_without_a_key_because_the_whole_map_may_be_requested() {
        GcpSecretLocation location = location("secret://gcp/db-credentials");

        assertThat(location.secret()).isEqualTo("db-credentials");
    }
}
