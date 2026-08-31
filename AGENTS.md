# Agent guidance — gravitee-secret-provider-gcp

Read this before changing anything about how the EL shim registers itself, or before bumping the
target APIM version. Most of what follows was established by inspecting the shipped 4.12.12 jars,
not from documentation — Gravitee documents almost none of it, and several plausible-sounding
assumptions about it are wrong.

## Reading the runtime versions off the image

Every Gravitee and third-party dependency is `provided`: the gateway supplies it at runtime. The
pinned versions in the root POM must therefore track the target APIM release. Read them off the
image rather than guessing — third-party jars are in `lib/ext`, not `lib`:

```bash
docker run --rm --entrypoint sh graviteeio/apim-gateway:4.12.12 \
  -c 'ls /opt/graviteeio-gateway/lib /opt/graviteeio-gateway/lib/ext'
```

The failure mode for getting this wrong is nasty and familiar from `gravitee-policy-token-exchange`:
the plugin loads, the gateway starts clean, and then every request fails with `NoSuchMethodError`,
because the JVM resolves methods by name **and descriptor**. A green startup proves nothing.

To copy files out of the image, note the container runs as non-root, so `-v $PWD:/out` fails with
permission denied. Use:

```bash
cid=$(docker create graviteeio/apim-gateway:4.12.12)
docker cp "$cid:/opt/graviteeio-gateway/plugins" .
docker rm "$cid"
```

## Verified facts about the secrets EL integration (APIM 4.12.12)

### `gravitee-secret-api` is 3.0.0 at runtime, not 1.0.0

The image ships `gravitee-secret-api-3.0.0.jar`. The OSS Kubernetes provider compiles against
`1.0.0` and still runs, because the **plugin SPI is byte-identical** between them —
`SecretProvider`, `SecretProviderFactory`, `SecretManagerConfiguration`, `SecretMap`, `Secret`,
`SecretEvent` are unchanged. What did change is everything EL- and discovery-facing:

- `EvaluatedSecretsMethods#fromEL` / `#fromGrant` return `Single<String>`, not `String`.
- `DelegatingEvaluatedSecretsMethods` also implements `DeferredFunctionHolder`.
- `SecretURL` gained `equals`/`hashCode`, based on **provider and path only** — not the key, and not
  the query string. Anything using a `SecretURL` as a map key gets that semantics; the cache in
  `CachingGcpSecretResolver` keys on `GcpSecretLocation` instead, which is why.
- `SecretSpec` gained `renewable` / `publishEventOnValueChanged` and the `?renewable=true` URI
  parameter.

So: the shim requires 3.0.0. The provider would work against either.

### The `secrets` EL variable is a designed extension point

`DelegatingEvaluatedSecretsMethods`' own Javadoc says it exists "to be white-listed in
expression-language dependency". The enterprise plugin registers it like this — verified by `javap`
on `com.graviteesource.service.secrets.el.engine.SecretsTemplateVariableProvider`:

```java
templateContext.setDeferredFunctionHolderVariable(
    "secrets", new DelegatingEvaluatedSecretsMethods(new DefaultEvaluatedSecretsMethods(...)));
```

annotated `@TemplateVariable(scopes = {API, HEALTH_CHECK})`. The variable name is `secrets`, plural.
(Note `EvaluatedSecretsMethods.DISABLED_ERROR_MESSAGE` says `{#secret.get(...)}`, singular — that
string is wrong; don't use it as a source.)

### In a licence-free gateway, `#secrets` is absent — not gracefully disabled

`EvaluatedSecretsMethods` carries `SECRETS_FEATURE_DISABLED = "[secrets feature disabled]"` and
`default String get(...)` returning it, which looks like an OSS fallback. **Nothing registers it.**
No class in `lib/` or `lib/ext/` ever constructs a `DelegatingEvaluatedSecretsMethods`; the only one
in the entire image that does is the enterprise plugin. Without a licence, `{#secrets.get(...)}`
fails outright with `EL1011E: Method call: Attempted to call method get(String) on null context
object`. Those interface defaults are dead code in the gateway.

Consequently there is no name collision to worry about in OSS — but there is the moment a licence is
added, which is what `SecretsModeExclusivity` is for.

### The enterprise plugin is gated by `feature=` in `plugin.properties`

`gravitee-service-secrets` declares `feature=gravitee-en-secrets`. `AbstractPluginHandler` asks
`isPluginDeployable(feature)`; `OSSLicense.isFeatureEnabled` returns `false` for any non-null
feature; `AbstractSpringPluginHandler` then skips creating the plugin's Spring context entirely.

**Our `plugin.properties` must never gain a `feature=` key.** The OSS Kubernetes provider has none;
the Vault one has `feature=gravitee-en-secretprovider-vault`.

### `setDeferredFunctionHolderVariable` is required, not merely preferable

A method returning `Single`/`Maybe` is unwrapped by `SpelTemplateEngine.eval`'s terminal `flatMap`
— but **only when the whole expression is that one call**. Measured against the real jars:

| Registered with | `{#secrets.get('/gcp/a:b')}` | `Bearer {#secrets.get('/gcp/a:b')}` | `...get(...).length()` |
| --- | --- | --- | --- |
| `setVariable` | works | `ClassCastException: SingleJust cannot be cast to String` | `EL1004E ... on type SingleJust` |
| `setDeferredFunctionHolderVariable` | works | works | works |

Only the deferred-holder registration makes `CachedExpression` rewrite the expression, hoisting each
sub-expression that touches the holder into a synthetic deferred variable resolved *before* the
surrounding expression is evaluated. `GcpSecretsElEvaluationTest` covers all four composite shapes;
do not "simplify" it to the bare case.

### The deferral rewrite is textual, and it mangles a nested call chain

The hoisting above is not an AST transformation — `CachedExpression` rebuilds each deferred
sub-expression by calling `toStringAST()` on a list of collected nodes and then splices it back with
`String.replaceAll`. Two things follow, both established by evaluating against the real EL 4.4.0 and
reading its sources:

`computeVariables(CompoundExpression, …)` collects nodes into `deferExpressionNodes` only for
`VariableReference`, `PropertyOrFieldReference`, `MethodReference` and `Indexer`. A **`TypeReference`
falls to the `else` branch and is never collected**, so for
`T(java.util.Base64).getEncoder().encodeToString(… #secrets.get(…) …)` the hoisted text comes out as
`getEncoder().encodeToString(…)` — receiver gone.

Whether that malformed entry survives depends on the shape of the *whole* value:

| Value | Parses as | Outcome |
| --- | --- | --- |
| `{T(…).getEncoder().encodeToString(('id:' + #secrets.get(…)).getBytes())}` | `SpelExpression` | **works** — `computeFinalExpression` removes `lastDeferVariable` because the AST does not start with a `Literal`, discarding the malformed entry |
| `Basic {T(…)…}` — any literal text around it | `CompositeStringExpression` | **silently wrong** — that branch never runs, the malformed text is spliced in, and expression fragments go upstream as the header value |
| `Bearer {#secrets.get(…)}` — a bare holder call | `CompositeStringExpression` | works — the two-node compound is collected correctly |

Nothing is logged in the failing case. This is what `GcpSecretsElHolder#basic` exists to avoid, and
both rows are pinned in `GcpSecretsElEvaluationTest` — including the known-bad one, so a future
Gravitee fix shows up as a test failure rather than staying invisible.

Separately, `SpelExpressionParser.EXPRESSION_REGEX` only rewrites `{#`, `{T` and `{(` into the `{#`
parser prefix. **An expression opening with anything else is not an expression**: `{'id:' +
#secrets.get(…)}` is a `LiteralExpression` and is emitted verbatim, braces and all.

Two further consequences:

- `TemplateEngine.evalNow` / `getValue` bypass the whole mechanism (no `CachedExpression`, no
  deferral, no unwrapping), so `#secrets` cannot work on synchronous evaluation paths. Pinned by a
  test so it reads as a known limitation rather than a bug.
- `TemplateContextAdapter.setDeferredFunctionHolderVariable` — the v3-policy adapter context — is an
  empty method body. Deferred holders are silently dropped there. V4 only.

### EL only calls whitelisted methods

`SecuredResolver` loads a `whitelist` classpath resource, plus `el.whitelist.list` from
configuration (`mode: append` keeps the built-ins, `replace` drops them). `getMethods(type)` walks
the type, its superclasses **and its interfaces**, so whitelisting a method on an interface covers
every implementer.

The built-in list whitelists exactly five secrets methods: `EvaluatedSecretsMethods.get(String)`,
`get(String,String)`, and `DelegatingEvaluatedSecretsMethods`' three `fromGrant`/`fromEL` overloads.
The two `get` overloads return `String`, which is why implementing that interface would force a
blocking design. Our `Single`-returning `get` is a different signature and needs the two
`el.whitelist.list` entries documented in the README.

Beware when testing: `SecuredResolver.initialize` loads the whole whitelist eagerly, and a missing
parameter type raises `NoClassDefFoundError`, which its per-declaration `try`/`catch` does not catch
— the entire whitelist then fails to load. That is why the `el` module has test-scoped
`bcpkix-jdk18on` and `gravitee-gateway-api`.

### How a `TemplateVariableProvider` is discovered — and the two traps

`AbstractReactorFactory.commonTemplateVariableProviders()` collects beans of type
`TemplateVariableProviderFactory` visible via `beanNamesForTypeIncludingAncestors`, filters on
`getTemplateVariableScope() == API`, and flat-maps their providers. One level down,
`ApiTemplateVariableProviderFactory` scans **beans** of type `TemplateVariableProvider` filtered by
the `@TemplateVariable` annotation. `AbstractSpringFactoriesLoaderTemplateVariableProviderFactory`
does **not** read `spring.factories` despite its name; its body is purely that bean scan.

**Trap 1 — the obvious `spring.factories` key is dead code.** Nothing in 4.12.12 reads
`io.gravitee.el.TemplateVariableProvider`. The single declaration of it, in
`gravitee-apim-gateway-reactor`, is vestigial: `NodeTemplateVariableProvider` actually becomes a bean
through an `@Bean` method in `ReactorConfiguration`, and its constructor takes
`(Node, GatewayConfiguration)`, which no factories loader could satisfy. Declaring our provider under
that key gets it silently ignored — no error, just no `#secrets`.

The keys a `SpringFactoriesLoader` in the gateway both reads *and* registers beans from:

| Key | Lands in | Notes |
| --- | --- | --- |
| `io.gravitee.plugin.core.api.PluginHandler` | main context | what we use; `Node`, `EventManager`, plugin managers all injectable |
| `io.gravitee.node.container.ContainerInitializer` | boot context | marker interface, but only sees `Configuration`/`Environment` |
| `io.gravitee.plugin.core.api.BootPluginHandler` | boot context | |

So `GcpSecretsTemplateVariableProvider implements PluginHandler` purely as a registration hook, with
`canHandle()` returning `false`. Note the loader instantiates each declared class **twice** — once as
a throwaway during loading, with all constructor arguments `null` — hence the no-argument
constructor and `*Aware` injection, with all real work deferred to `afterPropertiesSet()`.

**Trap 2 — `lib/ext` is the wrong directory, and it fails at boot.** `Bootstrap` builds a two-level
chain: `extensionClassLoader` over `lib/ext` (parent: app), then `graviteeClassLoader` over `lib`
(parent: `extensionClassLoader`). A class *defined by* the extension loader therefore cannot see
`lib/`, where `gravitee-expression-language` lives. Verified by running the gateway with a probe jar
in `lib/ext`:

```
IllegalArgumentException: Unable to instantiate factory class [probe.InitProvider]
Caused by: java.lang.NoClassDefFoundError: io/gravitee/el/TemplateVariableProvider
```

exit code 1. **The shim jar goes in `lib/`**, together with the core jar — a plain jar bundles
nothing, unlike the plugin ZIP.

Also note `@TemplateVariable` is read off the concrete class by raw reflection and is **not**
`@Inherited`: it must stay on `GcpSecretsTemplateVariableProvider` itself, and the bean must not be
CGLIB-proxied or the annotation is lost.

For contrast, the enterprise plugin cannot use any of this: a plugin's Spring context is a child,
invisible to the reactor factory, and it starts *after* context refresh — by which point
`AbstractSpringFactoriesLoaderTemplateVariableProviderFactory` has already cached its provider list.
That is why it registers a `TemplateVariableProviderFactory` singleton into the parent context
instead.

## `GraviteeConfigurationSecretResolver` caches forever

`resolve()` memoises every `SecretMap` in `Collections.synchronizedMap(new HashMap<>())` keyed by
path, and returns the cached value on any subsequent call. **It never evicts, and it ignores the
expiry the SPI carries.** Fine for `gravitee.yml`, resolved once at startup; fatal for request-time
use, where it would make `secretTtlSeconds` meaningless and rotation invisible until restart.

This is why `CachingGcpSecretResolver` talks to the Secret Manager client directly instead of
delegating to that resolver, even though delegating would have been less code. Do not "simplify" it
back — there is a test for the TTL, but the reason is here.

## Repo conventions

- Java 21, Maven, three modules: `core` (the only GCP-aware code), `plugin` (the ZIP), `el` (the
  `lib/ext` jar).
- `mvn verify` runs `prettier:check` and `license:check` at `validate`. `mvn prettier:write
  license:format` fixes both. `-Dskip.validation=true` skips them for a fast loop.
- gravitee-parent's ArchUnit rules are switched off (`gravitee.archrules.skip`): they enforce
  Gravitee's internal logging facade, which is not part of the plugin SPI. SLF4J is correct here, as
  it is for the OSS Kubernetes provider.
- Tests: JUnit 5 + AssertJ + RxJava `TestObserver` (`.test().awaitDone(...)`), WireMock for both
  Google endpoints. No Testcontainers — nothing here needs a gateway running to be tested, with the
  exception noted below.
- Never log a secret value, a payload, or an access token. Log the secret name, project and version.

## Not yet done

- No integration test against a real gateway. The gateway-SDK test mirroring
  `KubernetesSecretProviderIntegrationTest`, and an A2 test resolving a secret in a deployed API
  definition, are still to write. `GcpSecretsElEvaluationTest` covers the EL contract against the
  real EL implementation, which is the part most likely to break, but it does not prove plugin
  loading or bean discovery inside a running gateway.
- Deployment is out of scope for this repo: getting the artifacts onto a gateway (baked into an
  image or mounted) and wiring `secrets.gcp.*` plus the `el.whitelist.list` entries through whatever
  manages your gateway configuration.
