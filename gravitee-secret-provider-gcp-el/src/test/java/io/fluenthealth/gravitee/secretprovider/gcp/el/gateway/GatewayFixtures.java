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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.slf4j.Logger;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

/**
 * Shared pieces every gateway integration test needs.
 *
 * <p>{@code GcpGatewayBootstrapIT} still carries its own copies of these; it predates this class and
 * that duplication should collapse onto it rather than being left to drift.
 */
final class GatewayFixtures {

    /** Where {@link #gatewayWith} mounts the local API registry, and what the config must point at. */
    static final String LOCAL_REGISTRY_DIR = "/opt/graviteeio-gateway/apis";

    private static final String GATEWAY_HOME = "/opt/graviteeio-gateway";

    private GatewayFixtures() {}

    /**
     * A gateway with the plugin ZIP, both jars, the given configuration and a local API registry
     * installed. Ports 8082 (proxy) and 18082 (node API) are exposed.
     *
     * @param localRegistry a host directory of {@code *.json} definitions, mounted at
     *     {@link #LOCAL_REGISTRY_DIR}
     */
    static GenericContainer<?> gatewayWith(String apimVersion, Path graviteeYml, Path localRegistry, Logger log) {
        return new GenericContainer<>("graviteeio/apim-gateway:" + apimVersion)
            .withCopyFileToContainer(
                MountableFile.forHostPath(artifact("gravitee-secret-provider-gcp-plugin", "gravitee-secret-provider-gcp-*.zip")),
                GATEWAY_HOME + "/plugins/gravitee-secret-provider-gcp.zip"
            )
            .withCopyFileToContainer(
                MountableFile.forHostPath(artifact("gravitee-secret-provider-gcp-el", "gravitee-secret-provider-gcp-el-*.jar")),
                GATEWAY_HOME + "/lib/gravitee-secret-provider-gcp-el.jar"
            )
            .withCopyFileToContainer(
                MountableFile.forHostPath(artifact("gravitee-secret-provider-gcp-core", "gravitee-secret-provider-gcp-core-*.jar")),
                GATEWAY_HOME + "/lib/gravitee-secret-provider-gcp-core.jar"
            )
            .withCopyFileToContainer(MountableFile.forHostPath(graviteeYml), GATEWAY_HOME + "/config/gravitee.yml")
            .withCopyFileToContainer(MountableFile.forHostPath(logbackXml()), GATEWAY_HOME + "/config/logback.xml")
            /*
             * Explicit 0755. The gateway runs as uid 1001 (graviteeio) and the image has no
             * /opt/graviteeio-gateway/apis, so Testcontainers creates it — without a mode it lands
             * unreadable by that user and LocalSyncManager dies with AccessDeniedException while the
             * gateway still starts cleanly.
             */
            .withCopyFileToContainer(MountableFile.forHostPath(localRegistry, 0755), LOCAL_REGISTRY_DIR)
            .withExposedPorts(8082, 18082)
            .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("gateway"))
            .waitingFor(Wait.forLogMessage(".*API Gateway .* started in .*\\n", 1))
            .withStartupTimeout(Duration.ofMinutes(3));
    }

    /** Locates an artifact built by the reactor. */
    static Path artifact(String moduleDir, String glob) {
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
     * A logback that actually emits this project's logs.
     *
     * <p>The gateway's shipped config raises {@code io.gravitee} to {@code INFO} and leaves
     * {@code <root level="WARN">}, so every {@code INFO} line from {@code io.fluenthealth} is
     * discarded. Any test that reads the gateway log for one of our lines measures nothing without
     * this — which is exactly how a previous measurement produced a confident false negative.
     */
    static Path logbackXml() {
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
}
