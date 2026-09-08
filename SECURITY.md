# Security Policy

## Reporting a vulnerability

Please email security@xalgorix.com with details. We acknowledge reports
within two business days and aim to ship a fix or mitigation on a
severity-driven schedule. Do not file public GitHub issues for
suspected vulnerabilities.

## Dashboard trust boundary

The scanner dashboard is a single-operator administration interface. All
sessions authenticated with its configured operator credentials have the same
permissions over scans and provider settings. Session tokens are not separate
user or tenant identities. Do not give these credentials to mutually untrusted
users or expose this API as a tenant-facing service. A hosted integration must
authenticate its own users and enforce scan ownership before accessing the
scanner through server-held credentials.

LLM provider URLs are trusted operator configuration. Private endpoints are
supported for local Ollama and OpenAI-compatible gateways. Configure endpoints
you trust to receive scan context and provider credentials; tenant-facing
applications must not forward customer-supplied provider URLs or credentials.

Web report logos must be uploaded through the dashboard. Logo references are
limited to the configured `logos` directory; arbitrary local image paths and
scan-directory relative paths are not accepted. Saved absolute paths within
the upload directory remain supported. Re-upload older external logos to use
them in web reports.

## Daily scan policy

The [`security-daily`](.github/workflows/security-daily.yml) GitHub Actions
workflow runs every day at 07:00 UTC (and on `workflow_dispatch`). It executes
`govulncheck ./...` against the Go module. When it reports a vulnerability the
project actually calls into, the run fails and a GitHub Issue labelled
`security` and `automated` is opened with the report attached as a workflow
artifact. The job skips (and logs a notice) if `go.mod` is absent, so the
schedule keeps running regardless.
