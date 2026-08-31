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
import java.nio.charset.StandardCharsets;
import java.util.Base64;
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
 *
 * <p>{@link #basic(String, String)} is the one exception: the enterprise plugin has no equivalent,
 * so a definition using it is <em>not</em> licence-portable. It exists because the composition it
 * replaces cannot be expressed in EL at all — see its javadoc.
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
        return Single.defer(() -> resolver.resolveKey(toSecretURL(uriOrName, key, "get")));
    }

    /**
     * Resolves a secret and returns a complete HTTP Basic credential —
     * {@code Basic base64(username ":" secret)} — ready to be a header value.
     *
     * <h2>Why this exists, rather than composing it in EL</h2>
     *
     * The composition looks expressible:
     *
     * <pre>{@code
     * Basic {T(java.util.Base64).getEncoder().encodeToString(('id:' + #secrets.get('/gcp/s:value')).getBytes())}
     * }</pre>
     *
     * It is not, and it fails <em>silently</em>. Gravitee hoists every sub-expression that touches a
     * deferred holder into a synthetic variable resolved before the surrounding expression, but it
     * builds that sub-expression textually from the SpEL AST — and
     * {@code CachedExpression.computeVariables(CompoundExpression, …)} never collects the
     * {@code TypeReference} node, so the hoisted text loses its {@code T(java.util.Base64).}
     * receiver. When the whole value is that one expression the malformed entry is discarded again
     * (the {@code SpelExpression} branch of {@code computeFinalExpression} drops it because the AST
     * does not start with a literal) and it happens to work. Add any literal text around it — the
     * mandatory {@code Basic } prefix, for instance — and the value becomes a
     * {@code CompositeStringExpression}, that discard no longer runs, and the mangled expression is
     * substituted in by {@code replaceAll}. No error is raised: the header goes upstream carrying
     * expression fragments instead of a credential, and the far end answers 401.
     *
     * <p>Returning the finished credential keeps the call site in the shape that is proven to work —
     * a single holder call, with nothing nested around it:
     *
     * <pre>{@code
     * {#secrets.basic('/gcp/emr-bots-client-secret:value', 'emr-bots')}
     * }</pre>
     *
     * <p>The {@code Basic } prefix is included deliberately, rather than left to the call site, so
     * that no caller has to reintroduce a literal prefix.
     *
     * <h2>No URL-encoding</h2>
     *
     * The components are joined verbatim. This is a plain Basic credential as RFC 7617 defines it,
     * which is what {@code transform-headers} needs. It is <em>not</em> the OAuth2 client
     * authentication of RFC 6749 §2.3.1, where each component is form-urlencoded first — that
     * belongs to whatever presents client credentials to a token endpoint (in our case the
     * {@code oauth2-token-orchestrator} policy, which builds the header itself from a
     * {@code clientId}/{@code clientSecret} pair and does not need this method). Do not add encoding
     * here to serve that case: it would silently corrupt every existing Basic header whose password
     * contains a reserved character.
     *
     * @param uriOrName a secret URI such as {@code /gcp/my-secret:password}, holding the password
     * @param username the user name, a literal — resolve it with a nested expression and you are
     *     back to the problem above
     * @return {@code Basic <base64>}, resolved without blocking the calling thread
     */
    public Single<String> basic(String uriOrName, String username) {
        // Deferred for the same reason as get: a bad argument becomes an error signal rather than an
        // exception thrown inline into SpEL.
        return Single.defer(() -> {
            if (username == null || username.isBlank()) {
                // Matches get's treatment of a blank URI: say so rather than send half a credential.
                throw new SecretManagerException("#secrets.basic(...) was called with no user name");
            }
            SecretURL secretURL = toSecretURL(uriOrName, null, "basic");
            return resolver
                .resolveKey(secretURL)
                .map(secret -> {
                    // Explicit UTF-8: the platform default would make the header depend on the
                    // gateway's locale, and a non-ASCII password would encode differently per node.
                    byte[] credentials = (username + ":" + secret).getBytes(StandardCharsets.UTF_8);
                    return "Basic " + Base64.getEncoder().encodeToString(credentials);
                });
        });
    }

    private static SecretURL toSecretURL(String uriOrName, String key, String method) {
        if (uriOrName == null || uriOrName.isBlank()) {
            throw new SecretManagerException("#secrets.%s(...) was called with no secret URI".formatted(method));
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
