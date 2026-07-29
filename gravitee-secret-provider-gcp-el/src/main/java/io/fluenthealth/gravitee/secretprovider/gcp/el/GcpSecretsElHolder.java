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

import io.fluenthealth.gravitee.secretprovider.gcp.core.CachingGcpSecretResolver;
import io.gravitee.el.spel.context.DeferredFunctionHolder;
import io.gravitee.secrets.api.core.SecretURL;
import io.gravitee.secrets.api.errors.SecretManagerException;
import io.reactivex.rxjava3.core.Single;
import java.util.Objects;

/**
 * Backs the {@code secrets} EL variable, so that an API definition can say
 * {@code {#secrets.get('/gcp/my-secret:password')}} on a licence-free gateway.
 *
 * <h2>Why the methods return {@code Single<String>}</h2>
 *
 * SpEL invokes a variable's methods inline, on the caller's thread — which at request time is a
 * gateway event loop. Blocking there to fetch a secret would produce blocked-thread warnings and
 * latency spikes under load. Returning a {@link Single} avoids it: {@code SpelTemplateEngine} knows
 * how to resolve a reactive result without blocking, provided the holder is registered with
 * {@code TemplateContext#setDeferredFunctionHolderVariable} — see
 * {@link GcpSecretsTemplateVariableProvider}, and note that plain {@code setVariable} is <em>not</em>
 * equivalent: with it, only an expression consisting of nothing but this call works, and anything
 * composite such as {@code Bearer {#secrets.get(...)}} fails with a {@code ClassCastException} as the
 * raw {@code Single} leaks into string concatenation.
 *
 * <h2>Why the method names and syntax match the enterprise plugin</h2>
 *
 * The enterprise {@code service-secrets} plugin registers the same variable name with the same
 * {@code get} signatures and the same leading-slash URI syntax. Keeping all three identical is what
 * makes acquiring a licence a deployment change — install the plugin, disable this shim — rather
 * than an edit to every API definition that references a secret.
 */
public class GcpSecretsElHolder implements DeferredFunctionHolder {

    /**
     * Must match the name the enterprise plugin registers, or the drop-in property is lost. Verified
     * against {@code SecretsTemplateVariableProvider} in {@code gravitee-service-secrets} 3.0.1.
     */
    public static final String EL_VARIABLE_NAME = "secrets";

    private static final String GCP_PROVIDER = "gcp";

    private final CachingGcpSecretResolver resolver;

    public GcpSecretsElHolder(CachingGcpSecretResolver resolver) {
        this.resolver = Objects.requireNonNull(resolver);
    }

    /**
     * @param uriOrName a secret URI such as {@code /gcp/my-secret:password}
     * @return the secret value, resolved without blocking the calling thread
     */
    public Single<String> get(String uriOrName) {
        return get(uriOrName, null);
    }

    /**
     * @param uriOrName a secret URI such as {@code /gcp/my-secret}
     * @param key the key to read out of the secret, for when it is not known statically
     */
    public Single<String> get(String uriOrName, String key) {
        // Deferred so a malformed URI surfaces as an error signal rather than an exception thrown
        // inline into SpEL, which would be reported as an opaque evaluation failure.
        return Single.defer(() -> resolver.resolveKey(toSecretURL(uriOrName, key)));
    }

    private static SecretURL toSecretURL(String uriOrName, String key) {
        if (uriOrName == null || uriOrName.isBlank()) {
            throw new SecretManagerException("#secrets.get(...) was called with no secret URI");
        }
        String uri = uriOrName.trim();
        if (!uri.startsWith("/")) {
            /*
             * The enterprise plugin also accepts a bare name, resolved against secret specs managed
             * in the console. There is no spec registry here, so rather than silently treat a name
             * as a path we say so — a typo'd URI is otherwise a confusing "secret not found".
             */
            throw new SecretManagerException(
                ("'%s' is not a secret URI. This gateway resolves secrets without the enterprise secrets service, " +
                    "which supports URIs only: use '/%s/<secret>[/<version>]:<key>'.").formatted(uriOrName, GCP_PROVIDER)
            );
        }
        if (key != null && !key.isBlank()) {
            uri = uri + SecretURL.URI_KEY_SEPARATOR + key.trim();
        }
        SecretURL secretURL = SecretURL.from(uri, true);
        if (!GCP_PROVIDER.equals(secretURL.provider())) {
            throw new SecretManagerException(
                "Secret URI '%s' names provider '%s', but this shim only resolves '%s' secrets".formatted(
                    uri,
                    secretURL.provider(),
                    GCP_PROVIDER
                )
            );
        }
        return secretURL;
    }
}
