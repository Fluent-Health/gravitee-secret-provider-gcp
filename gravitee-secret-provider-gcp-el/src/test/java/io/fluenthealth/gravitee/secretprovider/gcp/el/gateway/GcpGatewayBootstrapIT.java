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
package io.fluenthealth.gravitee.secretprovider.gcp.el.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

/**
 * Boots a real APIM gateway with both artifacts installed and asserts that the gateway accepts them.
 *
 * <p>Everything asserted here is a gateway-internal contract that no unit test can reach, and each one
 * was actually broken at some point while this was being written:
 *
 * <ol>
 *   <li><b>The gateway starts at all.</b> Proves the shim jar is in the right directory. In
 *       {@code lib/ext} it is loaded by a parent classloader that cannot see {@code lib/}, and the
 *       gateway dies with {@code NoClassDefFoundError: io/gravitee/el/TemplateVariableProvider}.
 *   <li><b>The shim is picked up as a plugin handler.</b> Proves the {@code META-INF/spring.factories}
 *       entry works. The obvious key, {@code io.gravitee.el.TemplateVariableProvider}, is dead code in
 *       4.12 — a shim declared under it is silently ignored, with no error anywhere.
 *   <li><b>The secret-provider plugin loads.</b> Proves the configuration class is discoverable.
 *       {@code SecretManagerConfigurationClassFinder} scans the factory's own package for a
 *       <em>direct</em> implementation of {@code SecretManagerConfiguration}; with the config class in
 *       another module the plugin fails to load and mode A1 is entirely dead — while reporting only
 *       "No secret-provider plugin found for provider id: 'gcp'", which reads like a missing plugin.
 * </ol>
 *
 * <h2>What this does NOT cover</h2>
 *
 * Request-time resolution of {@code {#secrets.get(...)}}, which needs a deployed API. That is not as
 * expensive as this comment used to claim: APIM 4.12 <em>does</em> ship a local registry
 * ({@code LocalSyncManager} / {@code LocalApiSynchronizer} in {@code services-sync}, behind
 * {@code services.sync.local.enabled} and {@code services.sync.local.path}), which deploys every
 * {@code *.json} in a watched directory. No MongoDB and no management API are required. See
 * AGENTS.md ("Not yet done") for the file format.
 *
 * <h2>Why this asserts on the shim's own startup line</h2>
 *
 * <p>It used to assert that the logs <em>mention</em> the provider class, which proved nothing: that
 * is satisfied by {@code AbstractPluginHandlerBeanRegistryPostProcessor} <em>listing</em> the class
 * name while registering its bean definition. It read as "the shim initialised" while proving only
 * "a bean definition was registered" — and that gap is how the wrong claim below survived. It now
 * asserts on the shim's own "active" line, which only {@code afterPropertiesSet} can emit.
 *
 * <p><b>The beans <em>are</em> instantiated at startup.</b> This comment previously said
 * {@code TemplateVariableProvider} beans are resolved lazily at first API deployment, so with no API
 * deployed the bean is never created and {@code afterPropertiesSet} never runs. That is wrong, and it
 * was inferred from log lines that were never going to appear: the gateway's default logback keeps
 * {@code io.fluenthealth} at the {@code WARN} root level, so the shim's own {@code INFO} startup
 * lines are discarded. Mount a {@code logback.xml} that raises {@code io.fluenthealth} to
 * {@code INFO} and the shim's "active" line appears on every boot, with no API deployed. Never read
 * the absence of one of our log lines as evidence about what ran.
 *
 * <p>Run with {@code mvn verify -Pintegration-test}.
 */
@Tag("gateway-integration")
@Testcontainers
class GcpGatewayBootstrapIT {

    private static final Logger log = LoggerFactory.getLogger(GcpGatewayBootstrapIT.class);

    private static final String APIM_VERSION = System.getProperty("apim.version", "4.12.12");
    private static final String HOLDER_CLASS = "io.fluenthealth.gravitee.secretprovider.gcp.el.GcpSecretsElHolder";
    private static final String PROVIDER_CLASS = "io.fluenthealth.gravitee.secretprovider.gcp.el.GcpSecretsTemplateVariableProvider";

    @Container
    private final GenericContainer<?> gateway = new GenericContainer<>("graviteeio/apim-gateway:" + APIM_VERSION)
        .withCopyFileToContainer(
            MountableFile.forHostPath(artifact("gravitee-secret-provider-gcp-plugin", "gravitee-secret-provider-gcp-*.zip")),
            "/opt/graviteeio-gateway/plugins/gravitee-secret-provider-gcp.zip"
        )
        /*
         * lib/, NOT lib/ext/ — see the class comment. The core jar has to come too: a plain jar
         * bundles nothing, unlike the plugin ZIP.
         */
        .withCopyFileToContainer(
            MountableFile.forHostPath(artifact("gravitee-secret-provider-gcp-el", "gravitee-secret-provider-gcp-el-*.jar")),
            "/opt/graviteeio-gateway/lib/gravitee-secret-provider-gcp-el.jar"
        )
        .withCopyFileToContainer(
            MountableFile.forHostPath(artifact("gravitee-secret-provider-gcp-core", "gravitee-secret-provider-gcp-core-*.jar")),
            "/opt/graviteeio-gateway/lib/gravitee-secret-provider-gcp-core.jar"
        )
        .withCopyFileToContainer(MountableFile.forHostPath(graviteeYml()), "/opt/graviteeio-gateway/config/gravitee.yml")
        .withCopyFileToContainer(MountableFile.forHostPath(logbackXml()), "/opt/graviteeio-gateway/config/logback.xml")
        .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("gateway"))
        .waitingFor(Wait.forLogMessage(".*Gravitee\\.io - API Gateway .* started in .*\\n", 1))
        .withStartupTimeout(Duration.ofMinutes(3));

    @Test
    void should_start_with_the_plugin_and_the_el_shim_installed() {
        String logs = gateway.getLogs();

        assertThat(gateway.isRunning()).isTrue();

        assertThat(logs)
            .as("the shim must actually INITIALISE, which only its own startup line proves")
            .contains("GCP secrets EL shim active");

        assertThat(logs)
            .as("the shim jar must not be loaded by a classloader that cannot see gravitee-expression-language")
            .doesNotContain("NoClassDefFoundError");
    }

    @Test
    void should_load_the_secret_provider_plugin_with_a_discoverable_configuration_class() {
        String logs = gateway.getLogs();

        assertThat(logs)
            .as("the configuration class must be a direct SecretManagerConfiguration implementation in the factory's package")
            .doesNotContain("No secret provider configuration class defined");

        assertThat(logs)
            .as("mode A1 is dead if the provider cannot be registered under its id")
            .doesNotContain("No secret-provider plugin found for provider id: 'gcp'");
    }

    /** Locates an artifact built by the reactor. */
    private static Path artifact(String moduleDir, String glob) {
        Path target = Path.of("..", moduleDir, "target");
        try (var files = Files.newDirectoryStream(target, glob)) {
            for (Path candidate : files) {
                return candidate;
            }
        } catch (IOException e) {
            throw new IllegalStateException("Could not list " + target.toAbsolutePath(), e);
        }
        throw new IllegalStateException(
            "No artifact matching '%s' in %s. Run `mvn package` first.".formatted(glob, target.toAbsolutePath())
        );
    }

    /**
     * The gateway's shipped {@code logback.xml} raises {@code io.gravitee} to {@code INFO} and leaves
     * {@code <root level="WARN">}, so every {@code log.info} from this jar's {@code io.fluenthealth}
     * package is discarded. Without this override the shim's own startup lines never appear, and any
     * assertion that looks for them measures nothing — which is exactly the trap described in the
     * class comment.
     */
    private static Path logbackXml() {
        String xml = """
            <configuration>
                <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
                    <encoder>
                        <pattern>%d{HH:mm:ss.SSS} [%thread] [%X{api}] %-5level %logger{36} - %msg%n</pattern>
                    </encoder>
                </appender>
                <logger name="io.gravitee" level="INFO" />
                <logger name="com.graviteesource" level="INFO" />
                <logger name="io.fluenthealth" level="DEBUG" />
                <logger name="org.springframework" level="WARN" />
                <root level="WARN">
                    <appender-ref ref="STDOUT" />
                </root>
            </configuration>
            """;
        try {
            Path file = Files.createTempDirectory("gcp-secret-logback").resolve("logback.xml");
            Files.writeString(file, xml);
            return file;
        } catch (IOException e) {
            throw new IllegalStateException("Could not write logback.xml", e);
        }
    }

    private static Path graviteeYml() {
        /*
         * `management.type: none` selects the shipped repository-noop plugin. Without a repository
         * type the gateway refuses to start ("No repository type defined in configuration for
         * management") because it still binds the mongodb repository plugin.
         *
         * secrets.gcp points at an unreachable host on purpose: nothing is resolved at startup
         * because no `secret://` reference exists, and the point here is that the plugin *loads*.
         */
        String yml = """
            node:
              type: gateway

            management:
              type: none
            ratelimit:
              type: none

            services:
              sync:
                enabled: false
              core:
                http:
                  enabled: false

            analytics:
              type: none

            secrets:
              gcp:
                enabled: true
                projectId: example-project
                baseUrl: http://secret-manager.invalid
                metadataBaseUrl: http://metadata.invalid
                el:
                  enabled: true

            el:
              whitelist:
                mode: append
                list:
                  - method %s get java.lang.String
                  - method %s get java.lang.String java.lang.String
            """.formatted(HOLDER_CLASS, HOLDER_CLASS);
        try {
            Path file = Files.createTempDirectory("gcp-secret-bootstrap").resolve("gravitee.yml");
            Files.writeString(file, yml);
            return file;
        } catch (IOException e) {
            throw new IllegalStateException("Could not write gravitee.yml", e);
        }
    }
}
