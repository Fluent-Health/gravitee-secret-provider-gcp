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

import io.gravitee.el.TemplateVariableProviderFactory;
import java.util.Arrays;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;

/**
 * Enforces that mode A2 (this shim) and mode B (the enterprise secrets service) are never both
 * active.
 *
 * <p>Both register the EL variable {@code secrets}. Whichever provider runs last wins, and the order
 * depends on bean registration order — so with both present the gateway would resolve secrets
 * through one path or the other nondeterministically, with different caching, different error
 * handling and different access control. A silent precedence rule would hide that; failing to start
 * does not.
 */
final class SecretsModeExclusivity {

    /**
     * The enterprise service registers its {@code TemplateVariableProviderFactory} as a singleton in
     * the gateway's parent context, so it is visible here by type. Matching on the package rather
     * than loading the class matters: the class itself lives in the plugin's own classloader and is
     * not resolvable from this jar.
     */
    private static final String ENTERPRISE_SECRETS_PACKAGE = "com.graviteesource.service.secrets";

    private SecretsModeExclusivity() {}

    static void failIfEnterpriseSecretsServicePresent(ApplicationContext applicationContext) {
        if (applicationContext == null) {
            return;
        }
        String offender = findEnterpriseSecretsFactory(applicationContext);
        if (offender != null) {
            throw new IllegalStateException(
                ("""
                    Both the enterprise secrets service and the OSS GCP secrets EL shim are active, and both register \
                    the EL variable '%s' — which one wins is undefined.

                    Found: %s

                    Pick one:
                      * keep the enterprise service (mode B) and set %s=false; or
                      * remove the enterprise 'service-secrets' plugin from the gateway (mode A2).

                    API definitions do not need to change either way: both resolve \
                    {#%s.get('/gcp/<secret>:<key>')} identically.\
                    """).formatted(
                        GcpSecretsElHolder.EL_VARIABLE_NAME,
                        offender,
                        GcpSecretsTemplateVariableProvider.EL_ENABLED_PROPERTY,
                        GcpSecretsElHolder.EL_VARIABLE_NAME
                    )
            );
        }
    }

    private static String findEnterpriseSecretsFactory(ApplicationContext applicationContext) {
        return Arrays.stream(BeanFactoryUtils.beanNamesForTypeIncludingAncestors(applicationContext, TemplateVariableProviderFactory.class))
            .filter(name -> {
                Class<?> type = applicationContext.getType(name);
                return type != null && type.getName().startsWith(ENTERPRISE_SECRETS_PACKAGE);
            })
            .findFirst()
            .orElse(null);
    }
}
