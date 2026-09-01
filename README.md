# Gravitee Secret Provider — GCP Secret Manager

Load Gravitee APIM secrets straight out of **GCP Secret Manager**, instead of mirroring them into Kubernetes Secrets or baking them into configuration.

A project by [Fluent Health](https://github.com/Fluent-Health).

Ways to consume it, from one GCP client:

| Mode | Looks like | Licence | What resolves it |
| --- | --- | --- | --- |
| **A1** — configuration references | `secret://gcp/db-password:password` in `gravitee.yml` | none | OSS `GraviteeConfigurationSecretResolver`, at startup |
| **A2** — API definitions | `{#secrets.get('/gcp/db-password:password')}` | none | the EL shim in this repo, at request time |
| **A3** — API definitions, deploy time | `secret://gcp/db-password:password` in an API definition | none | the deploy-time substituter in this repo, **when the API deploys** |
| **B** — API definitions, enterprise | `{#secrets.get('/gcp/db-password:password')}` | **yes** | Gravitee's `service-secrets` plugin |

Modes A2 and B use **identical syntax**, so acquiring a licence is a deployment change — install the enterprise plugin, switch the shim off — and touches no API definition. See [Switching between A2 and B](#switching-between-a2-and-b).

**A2 is the default choice.** A3 exists only for policy fields that no expression language can reach, and it puts the resolved value inside the definition the gateway holds — see [Mode A3](#mode-a3--api-definitions-deploy-time), which is explicit about that cost. It is off unless you turn it on.

## Compatibility

Built and tested against **APIM 4.12.x** (verified at `4.12.12`).

Everything the plugin compiles against is `provided` — supplied by the gateway at runtime — so the pinned versions must track the target APIM release:

| Dependency | Version |
| --- | --- |
| `io.gravitee.secret:gravitee-secret-api` | `3.0.0` |
| `io.gravitee.el:gravitee-expression-language` | `4.4.0` |
| `io.gravitee.common:gravitee-common` | `5.0.0` |
| Vert.x | `5.0.12` |
| RxJava | `3.1.12` |

> **`gravitee-secret-api` is 3.0.0, not 1.0.0.** The OSS Kubernetes secret provider compiles against 1.0.0 and still runs here, because the plugin SPI (`SecretProvider`, `SecretMap`, `SecretURL`, `SecretManagerConfiguration`) is unchanged between the two. The EL-facing types are not: in 3.0.0 `EvaluatedSecretsMethods#fromEL`/`#fromGrant` return `Single<String>` rather than `String`. The shim needs 3.0.0.

See [AGENTS.md](./AGENTS.md) for how to re-read these off the gateway image after an APIM bump.

## Building

```bash
mvn verify
```

Produces two artifacts, which are deployed to different places:

| Module | Artifact | Goes to |
| --- | --- | --- |
| `gravitee-secret-provider-gcp-plugin` | `gravitee-secret-provider-gcp-<version>.zip` | `plugins/` (or `plugins-ext/`) |
| `gravitee-secret-provider-gcp-el` | `gravitee-secret-provider-gcp-el-<version>.jar` | **`lib/`** — not `lib/ext/` |

Mode A1 needs only the ZIP. Mode A2 needs both — the ZIP resolves nothing at request time on its own.

> **The shim jar must go in `lib/`, not `lib/ext/`.** The gateway loads `lib/ext` with a *parent* classloader that cannot see `lib/`, where `gravitee-expression-language` lives. Put the jar in `lib/ext` and the gateway fails to boot with `NoClassDefFoundError: io/gravitee/el/TemplateVariableProvider`. It also needs the `gravitee-secret-provider-gcp-core` jar alongside it in `lib/` — unlike the ZIP, a plain jar bundles nothing.

## Configuration

Under `secrets.gcp` in `gravitee.yml` (or as `GRAVITEE_SECRETS_GCP_*` environment variables). Every mode reads the same block, deliberately, so they cannot drift apart.

```yaml
secrets:
  gcp:
    enabled: true
    projectId: my-gcp-project # required when enabled
    defaultVersion: latest # version used when a URL names none
    secretTtlSeconds: 300 # how long a resolved secret is reused; see Rotation
    connectTimeoutMs: 3000
    requestTimeoutMs: 5000
    # serviceAccountKeyFile: /etc/gcp/sa.json   # LOCAL DEVELOPMENT ONLY
    el:
      enabled: true # mode A2 only; off by default
    deployTime:
      enabled: false # mode A3 only; off by default. Read the section first.
      rotationCheckSeconds: 60
```

| Property | Default | Notes |
| --- | --- | --- |
| `enabled` | `false` | Gates the whole provider. |
| `projectId` | — | Required when enabled. Startup fails without it. |
| `defaultVersion` | `latest` | Keep as `latest` unless you want to pin globally. |
| `secretTtlSeconds` | `300` | `0` disables expiry, which also disables rotation pickup. |
| `connectTimeoutMs` | `3000` | |
| `requestTimeoutMs` | `5000` | |
| `serviceAccountKeyFile` | — | Local development only. When unset, Workload Identity is used. |
| `el.enabled` | `false` | Activates the mode A2 shim. Requires the whitelist entries below. |
| `deployTime.enabled` | `false` | Activates mode A3. With it `false` the substituter subscribes to nothing and starts no thread, so 1.1.x behaviour is unchanged. |
| `deployTime.rotationCheckSeconds` | `60` | How often mode A3 re-resolves what it substituted. Independent of `secretTtlSeconds`, and pointless below it — the resolver cache would answer from memory. |

Mode A3 also accepts one modifier on a reference, `?encoding=base64` — see [that section](#encodingbase64).

### IAM

The gateway authenticates as its Workload Identity service account — no static key material. Grant it read access to each secret:

```bash
gcloud secrets add-iam-policy-binding db-password \
  --project my-gcp-project \
  --member "serviceAccount:apim-gateway@my-gcp-project.iam.gserviceaccount.com" \
  --role roles/secretmanager.secretAccessor
```

A `403` is reported with that exact role named in the error message.

## Secret URL syntax

Mode A1 uses the `secret://` scheme; mode A2 uses the leading-slash URI form. They are otherwise the same grammar.

```
secret://gcp/<secret>[/<version>][:<key>][?version=<version>]
        /gcp/<secret>[/<version>][:<key>]              (in EL)
```

| Example | Resolves |
| --- | --- |
| `secret://gcp/db-password:password` | key `password`, version `latest` |
| `secret://gcp/db-password` | the whole secret, under key `value` |
| `secret://gcp/db-password/7:password` | version 7, pinned |
| `secret://gcp/db-password:password?version=7` | same, version set independently of the path |
| `secret://gcp/tls:crt?keymap=certificate:crt` | maps `crt` onto the well-known `CERTIFICATE` key |

The project is **never** part of the URL — it comes from configuration, so an API definition cannot reach into another project. A path with more than two segments is rejected.

### How a payload becomes a secret map

A GCP secret version is one opaque blob; the rest of Gravitee expects a key/value map, the way a Kubernetes secret is. The convention:

- **Payload parses as a flat JSON object** → it *is* the secret map. One GCP secret can hold a whole credential set:
  ```json
  { "username": "apim", "password": "s3cr3t" }
  ```
  → `secret://gcp/db-credentials:username`
- **Anything else** (plain text, a JSON array, a *nested* JSON object) → opaque, exposed whole under the key from the URL, defaulting to `value`.

Nested objects count as opaque on purpose: a `SecretMap` is single-level, and inventing a path syntax to flatten into would be a worse surprise than handing the payload over intact.

`username`, `password`, `certificate`, `private_key` and the Kubernetes spellings `tls.crt` / `tls.key` map onto Gravitee's `WellKnownSecretKey` values automatically. An explicit `?keymap=` overrides that.

## Mode A1 — `gravitee.yml` references

Drop the ZIP into `plugins/`, set the configuration above, and reference secrets anywhere in `gravitee.yml`:

```yaml
ds:
  mongodb:
    password: secret://gcp/mongodb-credentials:password
```

Resolved once, at startup.

## Mode A2 — API definitions, no licence

Also install the EL shim jar (and the core jar) into `lib/`, set `secrets.gcp.el.enabled: true`, **and add three whitelist entries**:

```yaml
el:
  whitelist:
    mode: append
    list:
      - method io.fluenthealth.gravitee.secretprovider.gcp.el.GcpSecretsElHolder get java.lang.String
      - method io.fluenthealth.gravitee.secretprovider.gcp.el.GcpSecretsElHolder get java.lang.String java.lang.String
      - method io.fluenthealth.gravitee.secretprovider.gcp.el.GcpSecretsElHolder basic java.lang.String java.lang.String
```

Then, in any API definition:

```
{#secrets.get('/gcp/db-credentials:password')}
Bearer {#secrets.get('/gcp/api-token:token')}
{#secrets.get('/gcp/db-credentials', 'password')}
{#secrets.basic('/gcp/db-credentials:password', 'apim')}
```

### Basic-auth headers: use `#secrets.basic(...)`

`#secrets.basic('<uri>', '<username>')` returns a finished credential — `Basic base64(username:secret)` — ready to be a header value:

```
{#secrets.basic('/gcp/db-credentials:password', 'apim')}
```

Reach for it rather than assembling the header in the expression language, because **the obvious composition is silently broken**:

```
# DO NOT USE — sends expression fragments upstream, with no error
Basic {T(java.util.Base64).getEncoder().encodeToString(('apim:' + #secrets.get('/gcp/s:value')).getBytes())}
```

Gravitee hoists each sub-expression that touches a deferred variable into a synthetic variable resolved before the surrounding expression, but it rebuilds that sub-expression as *text* from the SpEL AST, and `CachedExpression` never collects the `T(java.util.Base64)` node — so the hoisted text loses its receiver. When the whole value is that one expression the malformed fragment is discarded again and it happens to work. Add any literal text around it, such as the mandatory `Basic ` prefix, and it is substituted in instead: the header goes upstream carrying expression fragments, the far end answers `401`, and nothing is logged.

Two related traps in the same area, neither specific to secrets:

- **An expression must open with `#`, `T` or `(`.** `SpelExpressionParser` only rewrites those three forms into its `{#` prefix, so `{'apim:' + #secrets.get('/gcp/s:value')}` is not an expression at all — the braces and the reference are sent verbatim as literal text.
- **A bare holder call is safe anywhere**, including inside a larger string: `Bearer {#secrets.get('/gcp/api-token:token')}` works. It is composition *around* the call, not surrounding literal text, that breaks.

Unlike `get`, `basic` has no enterprise equivalent, so a definition using it is **not** licence-portable — see [Switching between A2 and B](#switching-between-a2-and-b). Note also that a missing whitelist entry for `basic` fails *loudly*, as an evaluation error, rather than silently like the composition above.

### Raise this jar's log level, or you will not see why it failed

The gateway's shipped `logback.xml` sets `io.gravitee` to `INFO` and leaves `<root level="WARN">`. Nothing raises `io.fluenthealth`, so **every `INFO` line this plugin logs is discarded** — including the confirmation that the shim activated and the reminder about the whitelist entries. Add:

```xml
<logger name="io.fluenthealth" level="INFO" />
```

Without it you still get the important failure: a configuration where `secrets.gcp.enabled` and `secrets.gcp.el.enabled` disagree logs at `WARN` and survives the default root level, naming the switch to flip. What you lose is the positive confirmation, so add the logger when first wiring this up.

### Why the whitelist entries are mandatory

Gravitee's expression language refuses to call any method that is not on an allow-list (`SecuredResolver`, loaded from a `whitelist` classpath resource plus `el.whitelist.list`). The built-in list covers `EvaluatedSecretsMethods#get`, which returns a plain `String` — and a `String` return means resolving a secret would have to **block the event loop**.

This shim instead returns `Single<String>`, which the template engine resolves without blocking. That is a different method signature, so it needs its own two allow-list entries. Without them, expressions fail to evaluate. `mode: append` keeps the built-in list; `replace` would drop it.

`GcpSecretsElEvaluationTest` evaluates real expressions with exactly these entries — treat it as the source of truth if this section and the code ever disagree.

### Limitations of mode A2

- **Reactive evaluation paths only.** `#secrets` works wherever the gateway evaluates expressions reactively. It does **not** work on the synchronous `evalNow`/`getValue` path, nor in legacy v3 policies, whose adapter context silently ignores deferred function holders. Use it in V4 APIs.
- **URIs only, not names.** The enterprise service also resolves bare names against secret specs managed in the console. There is no spec registry here, so a non-URI argument is rejected with an explanatory error rather than guessed at.
- **No ACLs and no console UI** for secret specs. Access control is IAM on the GCP side.

## Mode A3 — API definitions, deploy time

**Off by default. Turn it on only for the fields mode A2 cannot reach, and read the exposure section below before you do.**

### The problem it solves

A request-time reference resolves only in a field the policy hands to `TemplateEngine.eval()`. That is the one entry point able to await a deferred value; `getValue`, `convert` and `evalNow` are synchronous and cannot. Several upstream policies never call `eval` on the field at all:

| Policy | Field | What it does instead |
| --- | --- | --- |
| `policy-generate-jwt` | `content` (the HMAC secret) | `new MACSigner(configuration.getContent())` — the raw string |
| `policy-request-validation` | ENUM constraint parameters | mapped through `templateEngine::convert` |
| `dynamic-routing` | rule `url` | `getValue` only |
| `policy-assign-content` | body | FreeMarker, not EL |

For those, no `{#secrets.get(...)}` will ever work — the policy sees the expression text, or a mangled fragment, and the far end answers 401 or 400 with nothing logged.

Mode A3 replaces the reference **inside the API definition, before the policy deserialises it**. It rewrites the whole raw configuration JSON of each plugin step, so eligibility stops being a per-field question: the policy receives a plain string whatever it does with it.

### Turning it on

Install the same artifacts as mode A2 (the plugin ZIP, plus both jars in `lib/`), then:

```yaml
secrets:
  gcp:
    enabled: true
    projectId: my-gcp-project
    deployTime:
      enabled: true
      rotationCheckSeconds: 60
```

No `el.whitelist` entries are needed — no expression language is involved. A3 and A2 can be on at once and are independent.

Then, in the API definition, use the same syntax as `gravitee.yml`:

```
secret://gcp/jwt-signing-key:value
secret://gcp/db-credentials:password
secret://gcp/upstream/2:token
```

Note this is **not** the `{#secrets.get(...)}` form. The two are deliberately distinguishable: one is substituted before deployment, the other evaluated per request. Mode A3 never touches an EL expression and mode A2 never touches a `secret://` reference, so `#secrets.get(...)` and `#secrets.basic(...)` behave identically whether A3 is on or off — and there is no deploy-time equivalent of them.

### Nothing is left in place silently

The failure this design most wants to avoid is a reference surviving into the deployed definition as literal text, travelling upstream as a credential, and coming back as a `401` that names nothing. So:

| What is in the field | What happens |
| --- | --- |
| A valid `secret://gcp/...` | Substituted. |
| A `secret://gcp/...` that cannot be parsed, resolved, or encoded | **The deployment fails**, with an error naming the reference and the plugin whose configuration it was found in. |
| `secret://<other-provider>/...` | Left alone — this plugin does not own it — but logged at `WARN`, so it reaches a default gateway. A misspelled provider (`secret://gpc/...`) is the likely cause. |

This is why the matcher is deliberately generous. A pattern that matched only *valid* references would leave a misspelled one in place, which is exactly the silent case.

### Where a reference ends

A reference does **not** have to be the whole field value — it can be embedded in a larger string, which is what a `dynamic-routing` url or a `policy-assign-content` body needs:

```
{#endpoints['default']}/V1/secret://gcp/two-factor-api-token:value/{#group[0]}
apikey=secret://gcp/two-factor-api-token:value&$${request.content}
```

Both work. The surrounding text — including a `$${...}` FreeMarker escape — is copied through untouched; only the matched reference is replaced.

The boundary rules:

| Rule | |
| --- | --- |
| Ends at any character that cannot appear in a secret URL | `"`, whitespace, `{`, `}`, `'`, … |
| **A trailing `/` is never part of the reference** | `SecretURL` strips trailing slashes, so one can only be the separator before whatever follows |
| **`&` counts only after a `?`** | outside a query string it separates form parameters |
| A query string *is* part of the reference | `...:value?encoding=base64` |

The two bolded rules exist because getting them wrong produces the worst failure this feature can: the *correct* secret substituted into a *mangled* string. Eating the `/` breaks the route; eating the `&` merges two form fields. Both were bugs in the first cut of this — right value, wrong string, and nothing downstream can tell.

**The one unsupported shape** is a reference that has a query string *and* is followed by `&`:

```
apikey=secret://gcp/tok:value?encoding=base64&$${request.content}   # rejected
```

Once a `?` is present, a following `&` is a parameter separator by URL grammar and cannot be distinguished from another parameter. Rather than guess, the deployment fails with `unrecognised query parameter`. Put the reference last in the value, or drop the query string.

Unknown query parameters are rejected for the same reason: `SecretURL` silently discards what it does not recognise, so `?encodng=base64` would otherwise be ignored. Only `encoding`, `version`, `keymap` and `watch` are accepted.

### The credential lifecycle is logged where you will actually see it

**No logging configuration is required.** The gateway's shipped `logback.xml` keeps `<root level="WARN">` and raises only `io.gravitee`, so mode A3 logs the credential lifecycle at `WARN` and it reaches a default gateway as-is:

| Line | When |
| --- | --- |
| `GCP deploy-time secret substitution ACTIVE ...` | once, at startup |
| `Retained N substitution(s) for Definition[kind=api-v4, id=X] revision R` | a credential was injected into a definition |
| `Released N retained substitution(s) for ...` | a definition was undeployed or superseded |
| `Publishing VALUE_CHANGED for ...` | a rotation was propagated in place |

`WARN` is not a claim that these are failures. They are audit-shaped rather than routine — each records a plaintext credential being written into, or dropped from, a live API definition that is then readable at `/_node/apis/<id>` — and the failure this feature has to make detectable is substitution **silently stopping**, which leaves a plausible-looking value in place and no error anywhere. A signal that does not survive the default configuration cannot be monitored for at all, not even by its absence. One line per definition, so the volume is one per API per deploy.

Per-*reference* detail stays at `INFO` — `Substituted a gcp reference at <plugin>` and `Secret value changed at <plugin>`. One line per definition is the audit record; one line per field is chatter. To see those, and the `INACTIVE`/`Ignoring REVOKE` diagnostics at `DEBUG`, add:

```xml
<logger name="io.fluenthealth" level="DEBUG" />
```

`GcpDeployTimeSecretRefsTest` pins both directions, so demoting a lifecycle line or promoting the chatter fails the build.

### `?encoding=base64`

Some fields want the credential base64-encoded rather than raw, and that requirement belongs to the **field**, not to the secret:

```
secret://gcp/jwt-signing-key:value?encoding=base64
```

The motivating case is a JWT plan's `resolverParameter` with `publicKeyResolver: GIVEN_KEY`. That field cannot use a request-time reference at all — `DefaultJWTProcessorProvider` reads it with `getValue`, which is synchronous — so it is deploy-time-only. And it needs the encoding, because `JWKBuilder.buildHMACKey` does:

```java
try {
    key = Base64.getDecoder().decode(keyValue);
} catch (IllegalArgumentException e) {
    key = keyValue.getBytes();
}
```

It base64-decodes if it can and falls back to raw bytes only when that throws. Pass a raw secret that *happens* to be valid base64 — plenty of alphanumeric secrets are — and the key silently becomes the decoded bytes, so every token on that plan is rejected with nothing logged. Encoding first makes the decode branch deterministic, so the key bytes are exactly the secret's bytes.

> This is HMAC-specific. `buildRSAKey` uses the value as a PEM or `ssh-rsa` string, where base64-encoding it would break the key. The encoding really is per-field, which is the point.

**Why a modifier rather than a second, pre-encoded secret.** Storing both works exactly once: the two copies then have to be rotated together, nothing about either opaque blob reveals that they have drifted, and A3's rotation would faithfully propagate whichever half was updated. One secret, encoded at the point of use, keeps rotation atomic.

The modifier is a query parameter because `SecretURL` already parses the query string, and this repo already uses it for `version` (`secret://gcp/my-secret:key?version=3`) as Gravitee does for `keymap` and `watch`. No new grammar. `encoding` may be set at most once, `base64` is its only supported value, and anything else fails the deployment rather than being ignored — `SecretURL` silently discards unknown parameters, so an unvalidated typo would go unnoticed.

### Rotation works without a gateway restart

Measured against `graviteeio/apim-gateway:4.12.12` with a real deployed API, not reasoned from source. Every `rotationCheckSeconds` the retained references are re-resolved; where a value moved it is written back through the setter the discovery SPI handed over and `VALUE_CHANGED` is published, which makes `ApiManagerImpl` fire `ReactorEvent.UPDATE` for the api object it already holds:

```
[graviteeio-node] Substituted a gcp reference at SecretRefsLocation[kind=plugin, id=transform-headers]
[graviteeio-node] Retained 1 substitution(s) for Definition[kind=api-v4, id=deploy-time-revoke] revision 1
[graviteeio-node] ApiManagerImpl - API id[deploy-time-revoke] revision[1] has been deployed
-- value changed in Secret Manager --
[gcp-deploytime-rotation] Publishing VALUE_CHANGED for Definition[kind=api-v4, id=deploy-time-revoke] so it redeploys in place
[gcp-deploytime-rotation] ApiManagerImpl - Secret value changed for API deploy-time-revoke, updating it
[gcp-deploytime-rotation] ApiManagerImpl - API id[deploy-time-revoke] revision[2] has been updated
```

One startup line in the whole run, one `/_node` identity throughout, the API updated in place and never re-registered, and the request after the rotation carrying the new value. `GcpDeployTimeSubstitutionIT` is that measurement.

A redeploy and an undeploy were measured too, by `GcpDeployTimeRevocationIT`, because the gateway publishes `DISCOVER` for the new revision **before** `REVOKE` for the previous one — so a superseded revision's revocation must not release what the live revision needs, and an undeploy must release it:

```
Retained 1 substitution(s) for Definition[kind=api-v4, id=deploy-time-revoke] revision 2
Ignoring REVOKE of Definition[kind=api-v4, id=deploy-time-revoke] revision 1; it is superseded by the retained revision 2
API id[deploy-time-revoke] revision[2] has been updated
-- value changed: rotation still reaches revision 2 --
Released 1 retained substitution(s) for Definition[kind=api-v4, id=deploy-time-revoke] revision 2
API id[deploy-time-revoke] revision[2] has been undeployed
-- value changed: nothing further is published for this api --
```

### The cost: the substituted value is readable at `/_node/apis/<id>`

Also measured. Once substituted, the plaintext is what the gateway holds, and `ApiManagementEndpoint` serialises the definition verbatim:

```json
"policy": "transform-headers",
"configuration": { "addHeaders": [{ "name": "X-Injected-Credential", "value": "the-actual-secret" }] }
```

The original `secret://gcp/...` reference is gone from that output — it has been replaced, not annotated.

> **Keep the node API authenticated.** The shipped `gravitee.yml` already binds `services.core.http` to `host: localhost` with `authentication.type: basic`, which is why the integration test has to set `host: 0.0.0.0` and `authentication.type: none` to read it at all. If you have widened that binding for probes or scraping, put credentials back on it before enabling mode A3. Mode A2 has no equivalent exposure, because nothing is ever written into the definition.

### Limitations of mode A3

- **A resolution failure fails the deployment.** The exception propagates out of `ApiManagerImpl.deploy`/`update`, so an API whose secret cannot be read does not deploy. This is deliberate: the alternative is serving a literal `secret://gcp/...` in a credential field. Rotation failures are different — they are logged and the value already in force stays.
- **In-place rotation covers V4 APIs only.** `ApiManagerImpl` acts on `VALUE_CHANGED` for the `api-v4` and `native-api-v4` definition kinds and ignores the rest. A reference in another kind of definition is still substituted at deploy time, but a later value change reaches it only when that definition is itself redeployed.
- **It is not licence-portable.** The enterprise `service-secrets` plugin has no deploy-time substitution, so a definition relying on A3 has to be rewritten before switching to mode B.
- **Two caches, not one.** A3 builds its own resolver, separate from the A2 shim's, so a secret used by both is fetched by both. At one fetch per TTL per secret that is not worth sharing state for.
- **The secret lands in JSON.** Quotes, backslashes and control characters are escaped so a value cannot break out of the string literal it is substituted into. Nothing else about the value is validated.
- **`base64` is the only encoding.** There is deliberately no general transform grammar. If a field ever needs a finished `Basic` credential the way `#secrets.basic(...)` provides one at request time, the modifier slot is where it would go — but the shape should be settled against a real call site, not guessed at now.

## Rotation

Point at `latest` (the default) and rotation needs no redeploy:

1. `resolve()` stamps the resulting `SecretMap` with an expiry of `now + secretTtlSeconds`.
2. Once that lapses, the next read goes back to Secret Manager and picks up the new version.

So `secretTtlSeconds` is the **upper bound on how long a rotation goes unnoticed**. Trade it off against Secret Manager request volume.

Two things worth knowing:

- **An explicitly pinned version never expires.** GCP secret versions are immutable, so there is nothing to re-read. Pinning also means every rotation becomes an API-definition change — which is why `latest` is the default.
- **`watch()` is a logged no-op.** GCP has no watch API: versions are immutable and creating one emits no subscribable signal. TTL-driven re-resolution is the mechanism, and the SPI requires `watch()` not to signal an error.

> **Mode A1 resolves at startup and caches for the lifetime of the process.** `GraviteeConfigurationSecretResolver` memoises every `SecretMap` in a map keyed by path and never evicts, ignoring the expiry the SPI carries. Rotating a secret referenced from `gravitee.yml` therefore requires a gateway restart. Modes A2 and A3 do not go through that resolver, precisely so its TTL means something.

Mode A3 adds a second interval on top of the TTL: it re-resolves what it substituted every `deployTime.rotationCheckSeconds` and redeploys the affected API in place. The worst case for A3 is therefore `secretTtlSeconds + rotationCheckSeconds`, and setting `rotationCheckSeconds` below the TTL buys nothing because the resolver cache answers from memory. See [Mode A3](#rotation-works-without-a-gateway-restart).

## Switching between A2 and B

No API definition changes, with one exception. The shim registers the EL variable `secrets` with the same `get` signatures and the same URI syntax as the enterprise plugin.

> **`#secrets.basic(...)` is ours alone.** The enterprise plugin does not provide it, so any definition using it has to be rewritten before switching to mode B — with `clientAuthMethod`-style support in the policy, or by composing the header in the enterprise EL, where the deferral bug above does not apply. Grep for `secrets.basic` before switching.

- **A2 → B:** install the enterprise `service-secrets` plugin, set `secrets.gcp.el.enabled: false`. Keep the secret-provider ZIP — mode B still resolves *through* it.
- **B → A2:** remove the enterprise plugin, set `secrets.gcp.el.enabled: true`, add the whitelist entries.
- **A3 → B:** not a deployment change. The enterprise plugin has no deploy-time substitution, so every `secret://gcp/...` reference inside an API definition has to be rewritten first. Grep for `secret://gcp/` in your definitions before switching.

**Both at once fails fast.** Both register `secrets`, and which one wins depends on bean registration order — so the shim refuses to start when it finds the enterprise service, with a message telling you which switch to flip. There is deliberately no silent precedence rule.

## Development

Prerequisites: JDK 21, Maven, and Docker for the integration test.

```bash
mvn verify                          # unit tests + prettier:check + license:check
mvn verify -Pintegration-test       # ... and boot a real gateway with the artifacts installed
mvn test -Dskip.validation=true     # fast loop, no lint
mvn prettier:write license:format   # fix formatting and licence headers
```

`-Pintegration-test` is what covers the parts of this that live in the gateway rather than in the
code. It needs Docker but no GCP account, and it runs on every pull request. Three suites, each
booting a real gateway:

| Suite | What it establishes |
| --- | --- |
| `GcpGatewayBootstrapIT` | The artifacts load and the beans initialise — classloader placement, the `spring.factories` registration, secret-provider configuration discovery. No API is deployed. |
| `GcpDeployTimeSubstitutionIT` | Mode A3 rotation with no gateway restart, and the `/_node/apis/<id>` exposure, against a deployed API served through a local registry. |
| `GcpDeployTimeRevocationIT` | Mode A3 across a redeploy and an undeploy: a superseded revision's `REVOKE` does not release what the live revision needs, and an undeploy does release it. |

There is also an optional profile that resolves a secret out of a real GCP Secret Manager. It needs a
project, a token, and a secret of your own whose payload is a flat JSON object with `username` and
`password` keys:

```bash
export GCP_ACCESS_TOKEN=$(gcloud auth print-access-token)
export GCP_PROJECT_ID=your-project
export GCP_E2E_SECRET_NAME=your-secret
mvn verify -Pgcloud-integration-test
```

Its assertions are structural, so any secret of that shape works. It is skipped in CI for forks,
since GitHub does not issue OIDC tokens to fork pull requests.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Bug reports and pull requests are welcome; no CLA is
required.

Reporting a security issue: see [SECURITY.md](./SECURITY.md) — please use private vulnerability
reporting rather than a public issue.

## Licence

[Apache 2.0](./LICENSE).
