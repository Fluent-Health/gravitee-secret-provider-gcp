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
import io.gravitee.el.TemplateContext;
import io.gravitee.el.TemplateVariableProvider;
import io.gravitee.el.TemplateVariableScope;
import io.gravitee.el.annotations.TemplateVariable;
import io.gravitee.plugin.core.api.Plugin;
import io.gravitee.plugin.core.api.PluginHandler;
import io.vertx.rxjava3.core.Vertx;
import io.vertx.rxjava3.ext.web.client.WebClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

/**
 * Registers the {@code secrets} EL variable so mode A2 works without an enterprise licence.
 *
 * <h2>How this class comes to exist at all</h2>
 *
 * It is declared in {@code META-INF/spring.factories} under the {@link PluginHandler} key, which is
 * one of the few keys a {@code SpringFactoriesLoader} in the gateway actually reads <em>and</em>
 * registers beans from. That is the entire reason this class implements {@link PluginHandler}: it
 * handles no plugins and {@link #canHandle(Plugin)} always returns {@code false}. The
 * {@code io.gravitee.el.TemplateVariableProvider} key that this would obviously want to use instead
 * is dead in APIM 4.12.x — nothing reads it. See AGENTS.md.
 *
 * <p>Once registered as a bean in the main context, discovery is the standard path:
 * {@code ApiTemplateVariableProviderFactory} scans beans of type {@link TemplateVariableProvider}
 * and filters on {@code @TemplateVariable} containing the {@code API} scope. The annotation is read
 * off the concrete class by raw reflection and is not {@code @Inherited}, so it must stay on this
 * class, and the bean must not be proxied.
 *
 * <p>Dependencies come through {@code *Aware} callbacks rather than the constructor because the
 * factories loader instantiates the class twice — once as a throwaway during loading, with all
 * constructor arguments {@code null} — so a no-argument constructor is the only safe shape. Nothing
 * expensive happens until {@link #afterPropertiesSet()}, which only the real bean reaches.
 *
 * <p><strong>This jar must be installed in {@code lib/}, not {@code lib/ext/}.</strong> Jars in
 * {@code lib/ext} are loaded by a parent classloader that cannot see {@code lib/}, where
 * {@code gravitee-expression-language} lives — the gateway then fails to boot with
 * {@code NoClassDefFoundError: io/gravitee/el/TemplateVariableProvider}.
 */
@TemplateVariable(scopes = { TemplateVariableScope.API, TemplateVariableScope.HEALTH_CHECK })
public class GcpSecretsTemplateVariableProvider
    implements TemplateVariableProvider, PluginHandler, EnvironmentAware, ApplicationContextAware, InitializingBean, DisposableBean {

    /** Set to {@code true} to activate the shim. Off by default: mode A2 is opt-in. */
    public static final String EL_ENABLED_PROPERTY = "secrets.gcp.el.enabled";

    private static final Logger log = LoggerFactory.getLogger(GcpSecretsTemplateVariableProvider.class);

    private Environment environment;
    private ApplicationContext applicationContext;

    private GcpSecretsElHolder holder;
    private Vertx vertx;
    private WebClient webClient;

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public void afterPropertiesSet() {
        GcpConfig config = GcpElConfigReader.read(environment);
        boolean elEnabled = environment.getProperty(EL_ENABLED_PROPERTY, Boolean.class, false);

        if (!config.isEnabled() && !elEnabled) {
            /*
             * Both switches off is a deliberate opt-out — mode A2 is opt-in and the jar is designed
             * to sit inert until someone asks for it. DEBUG, so a gateway that never wanted the shim
             * carries no noise about it.
             */
            log.debug("GCP secrets EL shim inactive: both secrets.gcp.enabled and {} are false.", EL_ENABLED_PROPERTY);
            return;
        }

        if (!config.isEnabled() || !elEnabled) {
            /*
             * WARN because that is the honest severity, not because of any log level it happens to
             * clear: one switch on and the other off cannot be what anyone meant, and the result is
             * a jar installed in lib/ doing nothing while '#secrets' expressions fail at request
             * time. Naming the switch to flip is the whole value of the line.
             *
             * Deliberately not a startup failure. SecretsModeExclusivity does throw for the
             * enterprise-service clash, but that is a different problem: there, two providers
             * register the same variable and something silently picks a winner. Here nothing is
             * ambiguous, and a gateway that refuses to boot is a worse outcome than one that logs
             * why a secret is not resolving. Considered and declined.
             */
            log.warn(
                "GCP secrets EL shim NOT ACTIVE because its two switches disagree: secrets.gcp.enabled={}, {}={}. " +
                    "'#secrets' is not registered by this jar, so every expression using it will fail. Set {} to true.",
                config.isEnabled(),
                EL_ENABLED_PROPERTY,
                elEnabled,
                config.isEnabled() ? EL_ENABLED_PROPERTY : "secrets.gcp.enabled"
            );
            return;
        }

        // Must happen before anything is registered: two providers of the same variable name would
        // resolve nondeterministically depending on bean ordering.
        SecretsModeExclusivity.failIfEnterpriseSecretsServicePresent(applicationContext);

        GcpResolverFactory.Resolver created = GcpResolverFactory.create(config, "gravitee-secret-provider-gcp-el");
        this.vertx = created.vertx();
        this.webClient = created.webClient();
        this.holder = new GcpSecretsElHolder(created.resolver());

        log.info(
            "GCP secrets EL shim active: '#{}.get(\"/gcp/<secret>[/<version>]:<key>\")' resolves from project '{}' " +
                "with a {}s TTL. Remember the two el.whitelist.list entries in gravitee.yml — without them EL refuses the call.",
            GcpSecretsElHolder.EL_VARIABLE_NAME,
            config.projectId(),
            config.secretTtl().toSeconds()
        );
    }

    @Override
    public void provide(TemplateContext templateContext) {
        if (holder == null) {
            return;
        }
        /*
         * setDeferredFunctionHolderVariable, not setVariable: it is what makes the engine rewrite
         * the expression so a Single-returning method resolves before the surrounding expression is
         * evaluated. See the class comment on GcpSecretsElHolder.
         */
        templateContext.setDeferredFunctionHolderVariable(GcpSecretsElHolder.EL_VARIABLE_NAME, holder);
    }

    /**
     * Always {@code false}. {@link PluginHandler} is implemented only to get this class registered as
     * a bean via {@code META-INF/spring.factories}; it handles no plugins.
     */
    @Override
    public boolean canHandle(Plugin plugin) {
        return false;
    }

    /** Never called, because {@link #canHandle(Plugin)} always refuses. */
    @Override
    public void handle(Plugin plugin) {
        // Intentionally empty; see canHandle.
    }

    @Override
    public void destroy() {
        if (webClient != null) {
            webClient.close();
        }
        if (vertx != null) {
            vertx.close().blockingAwait();
        }
    }
}
