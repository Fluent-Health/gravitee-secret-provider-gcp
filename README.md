# Gravitee Secret Provider — GCP Secret Manager

Load Gravitee APIM secrets straight out of **GCP Secret Manager**, instead of mirroring them into Kubernetes Secrets or baking them into configuration.

A project by [Fluent Health](https://github.com/Fluent-Health).

Two ways to consume it, from one GCP client:

| Mode | Looks like | Licence | What resolves it |
| --- | --- | --- | --- |
| **A1** — configuration references | `secret://gcp/db-password:password` in `gravitee.yml` | none | OSS `GraviteeConfigurationSecretResolver`, at startup |
| **A2** — API definitions | `{#secrets.get('/gcp/db-password:password')}` | none | the EL shim in this repo, at request time |
| **B** — API definitions, enterprise | `{#secrets.get('/gcp/db-password:password')}` | **yes** | Gravitee's `service-secrets` plugin |

Modes A2 and B use **identical syntax**, so acquiring a licence is a deployment change — install the enterprise plugin, switch the shim off — and touches no API definition. See [Switching between A2 and B](#switching-between-a2-and-b).

## Compatibility

Built and tested against **APIM 4.12.x** (verified at `4.12.12`).

Everything the plugin compiles against is `provided` — supplied by the gateway at runtime — so the pinned versions must track the target APIM release:

| Dependency | Version |
| --- | --- |
| `io.gravitee.secret:gravitee-secret-api` | `3.0.0` |
| `io.gravitee.el:gravitee-expression-language` | `4.4.0` |
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

Under `secrets.gcp` in `gravitee.yml` (or as `GRAVITEE_SECRETS_GCP_*` environment variables). Both modes read the same block, deliberately, so they cannot drift apart.

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

### Why the whitelist entries are mandatory

Gravitee's expression language refuses to call any method that is not on an allow-list (`SecuredResolver`, loaded from a `whitelist` classpath resource plus `el.whitelist.list`). The built-in list covers `EvaluatedSecretsMethods#get`, which returns a plain `String` — and a `String` return means resolving a secret would have to **block the event loop**.

This shim instead returns `Single<String>`, which the template engine resolves without blocking. That is a different method signature, so it needs its own two allow-list entries. Without them, expressions fail to evaluate. `mode: append` keeps the built-in list; `replace` would drop it.

`GcpSecretsElEvaluationTest` evaluates real expressions with exactly these entries — treat it as the source of truth if this section and the code ever disagree.

### Limitations of mode A2

- **Reactive evaluation paths only.** `#secrets` works wherever the gateway evaluates expressions reactively. It does **not** work on the synchronous `evalNow`/`getValue` path, nor in legacy v3 policies, whose adapter context silently ignores deferred function holders. Use it in V4 APIs.
- **URIs only, not names.** The enterprise service also resolves bare names against secret specs managed in the console. There is no spec registry here, so a non-URI argument is rejected with an explanatory error rather than guessed at.
- **No ACLs and no console UI** for secret specs. Access control is IAM on the GCP side.

## Rotation

Point at `latest` (the default) and rotation needs no redeploy:

1. `resolve()` stamps the resulting `SecretMap` with an expiry of `now + secretTtlSeconds`.
2. Once that lapses, the next read goes back to Secret Manager and picks up the new version.

So `secretTtlSeconds` is the **upper bound on how long a rotation goes unnoticed**. Trade it off against Secret Manager request volume.

Two things worth knowing:

- **An explicitly pinned version never expires.** GCP secret versions are immutable, so there is nothing to re-read. Pinning also means every rotation becomes an API-definition change — which is why `latest` is the default.
- **`watch()` is a logged no-op.** GCP has no watch API: versions are immutable and creating one emits no subscribable signal. TTL-driven re-resolution is the mechanism, and the SPI requires `watch()` not to signal an error.

> **Mode A1 resolves at startup and caches for the lifetime of the process.** `GraviteeConfigurationSecretResolver` memoises every `SecretMap` in a map keyed by path and never evicts, ignoring the expiry the SPI carries. Rotating a secret referenced from `gravitee.yml` therefore requires a gateway restart. Mode A2 does not go through that resolver, precisely so its TTL means something.

## Switching between A2 and B

No API definition changes, with one exception. The shim registers the EL variable `secrets` with the same `get` signatures and the same URI syntax as the enterprise plugin.

> **`#secrets.basic(...)` is ours alone.** The enterprise plugin does not provide it, so any definition using it has to be rewritten before switching to mode B — with `clientAuthMethod`-style support in the policy, or by composing the header in the enterprise EL, where the deferral bug above does not apply. Grep for `secrets.basic` before switching.

- **A2 → B:** install the enterprise `service-secrets` plugin, set `secrets.gcp.el.enabled: false`. Keep the secret-provider ZIP — mode B still resolves *through* it.
- **B → A2:** remove the enterprise plugin, set `secrets.gcp.el.enabled: true`, add the whitelist entries.

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
code — classloader placement, the `spring.factories` registration, and secret-provider configuration
discovery. It needs Docker but no GCP account, and it runs on every pull request.

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
