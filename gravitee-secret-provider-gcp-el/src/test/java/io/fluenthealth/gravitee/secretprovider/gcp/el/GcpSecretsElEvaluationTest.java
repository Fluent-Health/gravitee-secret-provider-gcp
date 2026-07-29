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

import io.fluenthealth.gravitee.secretprovider.gcp.core.CachingGcpSecretResolver;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpConfig;
import io.fluenthealth.gravitee.secretprovider.gcp.core.GcpSecretManagerClient;
import io.gravitee.el.TemplateEngine;
import io.gravitee.el.spel.context.SecuredResolver;
import io.reactivex.rxjava3.core.Maybe;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

/**
 * End-to-end evaluation through a real {@link TemplateEngine}. This is the test that actually holds
 * mode A2 together, because it exercises the two things that are easy to get wrong and impossible to
 * see from a unit test of the holder alone:
 *
 * <ol>
 *   <li>EL will only call a method that is on its whitelist. Our {@code get} methods are not on the
 *       built-in list — only {@code EvaluatedSecretsMethods}' {@code String}-returning ones are — so
 *       they must be added through {@code el.whitelist.list}. The entries used below are exactly the
 *       ones that have to appear in {@code gravitee.yml}; if this test is changed, that config has to
 *       change with it.
 *   <li>Returning a {@link io.reactivex.rxjava3.core.Single} only resolves correctly when the holder
 *       is registered with {@code setDeferredFunctionHolderVariable}. The composite cases below are
 *       the ones that fail with a bare {@code setVariable}.
 * </ol>
 *
 * <p>Note {@code SpelExpressionParser} caches parsed expressions in a static, JVM-wide map keyed by
 * the expression string, and a cached expression captures its deferral plan at first parse. Every
 * test therefore uses a distinct expression string.
 */
class GcpSecretsElEvaluationTest {

    /*
     * System clock, not a fixed one: SecretMap#isExpired compares against Instant.now(), so a fixed
     * clock makes cached entries expire in wall-clock terms once real time passes it plus the TTL.
     * Nothing here asserts a fetch count, so it would not fail — but it would silently stop
     * exercising the cache. See the longer note in GcpSecretsElHolderTest.
     */
    private static final Clock CLOCK = Clock.systemUTC();
    private static final String HOLDER = GcpSecretsElHolder.class.getName();

    /** The two lines that must be present under {@code el.whitelist.list} in {@code gravitee.yml}. */
    static final String WHITELIST_GET_URI = "method " + HOLDER + " get java.lang.String";
    static final String WHITELIST_GET_URI_AND_KEY = "method " + HOLDER + " get java.lang.String java.lang.String";

    private static final Set<String> requested = ConcurrentHashMap.newKeySet();

    @BeforeAll
    static void allowOurMethodsInEl() {
        StandardEnvironment environment = new StandardEnvironment();
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put(SecuredResolver.EL_WHITELIST_MODE_KEY, SecuredResolver.APPEND_WHITELIST_MODE);
        properties.put(SecuredResolver.EL_WHITELIST_LIST_KEY + "[0]", WHITELIST_GET_URI);
        properties.put(SecuredResolver.EL_WHITELIST_LIST_KEY + "[1]", WHITELIST_GET_URI_AND_KEY);
        environment.getPropertySources().addFirst(new MapPropertySource("whitelist", properties));
        SecuredResolver.initialize(environment);
    }

    private static TemplateEngine engineWith(String payload) {
        GcpSecretManagerClient client = (secret, version) -> {
            requested.add(secret);
            return Maybe.just(payload.getBytes(StandardCharsets.UTF_8));
        };
        GcpConfig config = new GcpConfig(Map.of("enabled", true, "projectId", "example-project", "secretTtlSeconds", 300));
        GcpSecretsElHolder holder = new GcpSecretsElHolder(new CachingGcpSecretResolver(client, config, CLOCK));

        TemplateEngine engine = TemplateEngine.templateEngine();
        engine.getTemplateContext().setDeferredFunctionHolderVariable(GcpSecretsElHolder.EL_VARIABLE_NAME, holder);
        return engine;
    }

    private static String eval(TemplateEngine engine, String expression) {
        return engine.eval(expression, String.class).test().awaitDone(5, TimeUnit.SECONDS).assertComplete().values().getFirst();
    }

    @Test
    void should_resolve_a_bare_secrets_expression() {
        TemplateEngine engine = engineWith("{\"password\":\"s3cr3t\"}");

        assertThat(eval(engine, "{#secrets.get('/gcp/el-bare:password')}")).isEqualTo("s3cr3t");
        assertThat(requested).contains("el-bare");
    }

    /**
     * The case that proves the deferred-function-holder registration is doing its job: with a plain
     * {@code setVariable} the raw {@code Single} reaches string concatenation and this fails with a
     * {@code ClassCastException}.
     */
    @Test
    void should_resolve_a_secret_interpolated_into_a_larger_string() {
        TemplateEngine engine = engineWith("plain-token");

        assertThat(eval(engine, "Bearer {#secrets.get('/gcp/el-header:value')}")).isEqualTo("Bearer plain-token");
    }

    @Test
    void should_allow_a_method_call_on_the_resolved_value() {
        TemplateEngine engine = engineWith("abcdef");

        assertThat(eval(engine, "{#secrets.get('/gcp/el-chained:value').length()}")).isEqualTo("6");
    }

    @Test
    void should_resolve_two_secret_references_in_one_expression() {
        TemplateEngine engine = engineWith("{\"username\":\"apim\",\"password\":\"s3cr3t\"}");

        String value = eval(engine, "{#secrets.get('/gcp/el-pair:username')}:{#secrets.get('/gcp/el-pair:password')}");

        assertThat(value).isEqualTo("apim:s3cr3t");
    }

    @Test
    void should_resolve_with_the_key_as_a_second_argument() {
        TemplateEngine engine = engineWith("{\"password\":\"s3cr3t\"}");

        assertThat(eval(engine, "{#secrets.get('/gcp/el-twoarg', 'password')}")).isEqualTo("s3cr3t");
    }

    @Test
    void should_surface_a_resolution_failure_as_an_evaluation_error_rather_than_a_bad_value() {
        TemplateEngine engine = engineWith("{\"username\":\"apim\"}");

        engine
            .eval("{#secrets.get('/gcp/el-missing-key:password')}", String.class)
            .test()
            .awaitDone(5, TimeUnit.SECONDS)
            .assertError(throwable -> throwable.getMessage() != null && throwable.getMessage().contains("el-missing-key"));
    }

    /**
     * {@code evalNow}/{@code getValue} skip the deferral machinery entirely, so a reactive holder
     * cannot work on those synchronous paths. Pinned here because it is the one real limitation of
     * this design and it must not regress into looking like a bug.
     */
    @Test
    void should_not_be_usable_on_the_synchronous_evaluation_path() {
        TemplateEngine engine = engineWith("plain-token");

        assertThat(engine.evalNow("{#secrets.get('/gcp/el-sync:value')}", Object.class)).isNotInstanceOf(String.class);
    }
}
