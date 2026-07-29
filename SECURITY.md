# Security

## Reporting a vulnerability

Please use [GitHub's private vulnerability reporting](https://github.com/Fluent-Health/gravitee-secret-provider-gcp/security/advisories/new) to report security issues. Do not open a public issue.

We aim to acknowledge reports within 5 business days and will keep you informed as we work toward a fix.

## Scope notes

This plugin reads secrets. A few properties are load-bearing, so please flag anything that undermines them:

- **No static credentials in production.** Authentication goes through the GKE metadata server (Workload Identity). `secrets.gcp.serviceAccountKeyFile` exists for local development only.
- **Secret values must not reach logs.** Nothing in this project logs a resolved secret value, a payload, or an access token. Log lines name the secret, the project and the version — never the contents.
- **A secret URL must not be able to leave the configured project.** The project comes from `secrets.gcp.projectId`; the URL supplies only a secret name and version, and both are URL-encoded into the request path.
