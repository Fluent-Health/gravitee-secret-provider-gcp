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

/**
 * Shared pieces every gateway integration test needs.
 *
 * <p>{@code GcpGatewayBootstrapIT} still carries its own copies of these; if the deploy-time spike
 * graduates, that duplication should collapse onto this class rather than being left to drift.
 */
final class GatewayFixtures {

    private GatewayFixtures() {}

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
