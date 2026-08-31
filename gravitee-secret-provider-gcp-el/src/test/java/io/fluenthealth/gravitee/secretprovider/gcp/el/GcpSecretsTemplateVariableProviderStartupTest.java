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

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

/**
 * Pins the severity of the three startup states, because the level is the feature here.
 *
 * <p>The gateway's shipped logback keeps {@code io.fluenthealth} at the {@code WARN} root level, so
 * an {@code INFO} diagnostic is discarded in every environment. The line that explains a
 * misconfiguration therefore has to be {@code WARN} — which is also its honest severity: a jar
 * installed in {@code lib/} and doing nothing. Anything that quietly demotes it back to {@code INFO}
 * makes the shim fail silently again, and that is what these tests exist to catch.
 */
class GcpSecretsTemplateVariableProviderStartupTest {

    private ListAppender<ILoggingEvent> appender;
    private Logger logger;

    @BeforeEach
    void captureLogs() {
        logger = (Logger) LoggerFactory.getLogger(GcpSecretsTemplateVariableProvider.class);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.TRACE);
    }

    @AfterEach
    void releaseLogs() {
        logger.detachAppender(appender);
        appender.stop();
    }

    private void start(Boolean providerEnabled, Boolean elEnabled) {
        Map<String, Object> properties = new LinkedHashMap<>();
        if (providerEnabled != null) {
            properties.put("secrets.gcp.enabled", providerEnabled);
        }
        if (elEnabled != null) {
            properties.put(GcpSecretsTemplateVariableProvider.EL_ENABLED_PROPERTY, elEnabled);
        }
        properties.put("secrets.gcp.projectId", "example-project");

        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("test", properties));

        GcpSecretsTemplateVariableProvider provider = new GcpSecretsTemplateVariableProvider();
        provider.setEnvironment(environment);
        provider.afterPropertiesSet();
    }

    private ILoggingEvent onlyEvent() {
        assertThat(appender.list).hasSize(1);
        return appender.list.getFirst();
    }

    /** Nobody asked for the shim. No noise. */
    @Test
    void should_stay_quiet_when_both_switches_are_off() {
        start(false, false);

        assertThat(onlyEvent().getLevel()).isEqualTo(Level.DEBUG);
    }

    @Test
    void should_warn_when_the_provider_is_enabled_but_the_shim_is_not() {
        start(true, false);

        ILoggingEvent event = onlyEvent();
        assertThat(event.getLevel()).as("an INFO here is discarded by the gateway's default logback").isEqualTo(Level.WARN);
        assertThat(event.getFormattedMessage())
            .as("the line has to name the switch to flip, or it does not help anyone")
            .contains(GcpSecretsTemplateVariableProvider.EL_ENABLED_PROPERTY);
    }

    @Test
    void should_warn_and_name_the_other_switch_when_only_the_shim_is_enabled() {
        start(false, true);

        ILoggingEvent event = onlyEvent();
        assertThat(event.getLevel()).isEqualTo(Level.WARN);
        assertThat(event.getFormattedMessage()).contains("secrets.gcp.enabled");
    }

    /** An absent property is a deliberate opt-out too, not a misconfiguration. */
    @Test
    void should_treat_absent_properties_as_an_opt_out_rather_than_a_disagreement() {
        start(null, null);

        assertThat(onlyEvent().getLevel()).isEqualTo(Level.DEBUG);
    }
}
