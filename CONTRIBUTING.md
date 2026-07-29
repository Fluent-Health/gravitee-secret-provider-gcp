# Contributing

Thanks for your interest in contributing.

## Reporting bugs

Open an issue describing the problem, steps to reproduce, and expected behaviour. For anything touching secret resolution, please include your `secrets.gcp.*` configuration with values redacted, and the APIM version.

## Proposing changes

1. Fork the repository.
2. Create a branch: `git checkout -b my-fix`.
3. Make your changes and commit with a clear message.
4. Open a pull request against `main`.

## Code style

Java 21. Formatting and licence headers are enforced by the build, both bound to the `validate` phase, so a badly formatted PR fails CI:

```bash
mvn verify                      # runs prettier:check + license:check + tests
mvn prettier:write license:format   # fix both in place
```

To iterate without the checks: `mvn test -Dskip.validation=true`.

## Before opening a PR

```bash
mvn verify
```

If you change anything about how the EL shim registers itself or what it returns, `GcpSecretsElEvaluationTest` is the test that matters — it evaluates real expressions through a real template engine. Please read its class comment first; the whitelist entries it declares have to stay in step with the ones documented in the README.

## No CLA required

You do not need to sign a Contributor License Agreement. By submitting a pull request, you agree to license your contribution under the repository's existing [LICENSE](./LICENSE).
