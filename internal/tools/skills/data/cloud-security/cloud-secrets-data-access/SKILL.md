---
name: cloud-secrets-data-access
description: Cloud secrets and data access — AWS Secrets Manager, SSM Parameter Store, Azure Key Vault, GCP Secret Manager, environment/CI-CD/deployment credentials, distinguishing visible names from retrievable values and test placeholders from live credentials
intent: offensive
assessment_mode:
  - blackbox
  - credentialed
provider:
  - aws
  - azure
  - gcp
---

# Cloud Secrets & Data Access

## Purpose
Enumerate and retrieve cloud-held secrets once any cloud context exists (credentials, metadata chain, or public exposure), then separate four very different states: name visible, value retrievable, placeholder, live credential.

## Entry Conditions
- A cloud identity (from `cloud-credential-abuse`) or a public exposure path (JS, config files, git, storage)
- Scope for secret retrieval governed by runtime policy — reading a secret value is an audit-visible, sometimes-irreversible action

## Discovery Signals
- Credentialed: Secrets Manager names, SSM parameter names, Key Vault certificate/secret/key lists, Secret Manager entries
- Black-box: `.env`/config in deployment bundles, source maps, git history, serverless packages, CI/CD variables exposed via public API metadata, storage bucket contents
- Token/audience: Key Vault requires its own audience (`https://<vault>.vault.azure.net`)

## Attack Model

```text
secret NAME visible   ≠  secret VALUE retrievable
test placeholder       ≠  live usable credential
```
Report the exact state proven. A name leak is an information disclosure; a value retrieval with a live downstream system is a full compromise chain.

## Methodology

### AWS
```bash
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <name>          # the actual retrieval
aws ssm describe-parameters                                       # names, KMS state, version
aws ssm get-parameter --name <name> --with-decryption
# Lambda/EC2/ECS env vars carry secrets too: check function configuration
aws lambda get-function-configuration --function-name <fn>
```

### Azure
```bash
# Key Vault needs the right audience; list first, then get
az keyvault list
az keyvault secret list --vault-name <vault>
az keyvault secret show --vault-name <vault> --name <secret>
# Automation accounts: az automation credential list; connection strings in app settings:
az webapp config appsettings list --name <app> -g <rg>
```

### GCP
```bash
gcloud secrets list
gcloud secrets versions access latest --secret=<name>
# Deployment/app config: GCS bucket next to the service, environment variables in Cloud Run/Functions:
gcloud run services describe <svc> --format="value(spec.template.spec.containers[0].env)"
```

### Black-Box Sources (no cloud identity needed)
- Deployment packages/layers of serverless functions when code disclosure exists
- CI/CD systems reachable via public API (pipeline variables, deployment tokens)
- Connection strings in error messages or exported configs
- Presigned URLs in JS pointing at config buckets

## Chaining
Every retrieved live credential goes to `cloud-credential-abuse` for validation and expansion. Database/connection-string credentials go to the corresponding network-service testing. Report the full chain: exposure point → secret → validated identity → impact.

## Evidence Contract

```text
secret name visible (list)         → information disclosure finding (low)
secret value retrievable           → retrieve, classify content (credential? key? PII?)
retrieved value validated live     → full chain finding with impact
retrieved value = test/placeholder → document as hygiene exposure, not compromise
```

**NOT evidence**: a secret existing (name) treated as value compromise, a placeholder value treated as a live credential, an unreadable (KMS-denied) secret treated as exposed

## Common Misses
- Parameter Store SecureString entries skipped (`--with-decryption` forgotten)
- Key Vault audience confusion (using an ARM token and concluding "no access")
- Lambda/ECS env vars and Cloud Run env never enumerated after secrets come up empty
- Secret VERSIONS (old values often linger with old passwords that still work)
- Managed-identity access to Key Vault never tested from the workload context
- CI/CD variable exposure in public pipeline definitions

## False Positives / Non-Findings
- RDS-generated credential placeholders in templates
- Dev/test vault contents with no production connectivity
- Names in `ListSecrets` without `GetSecretValue` (access properly denied at value level)

## Xalgorix Tool Strategy
- `terminal_execute` with aws/az/gcloud for enumeration and retrieval
- Python for parsing retrieved bundles (env files, key files)
- Every retrieved credential → ledger with validation state

## Specialist Handoffs
- Retrieved cloud credentials → `cloud-credential-abuse`
- API keys (SaaS) → api-security skills / credential-specific testing
- Database strings → network-services-pentesting skills

## Stopping Rule
For each secret surface: enumerate names once, retrieve values for a bounded set of high-signal targets (production-looking names), validate the top candidates live. Do not attempt every secret in a 1000-secret vault; prioritize by name and last-accessed metadata.