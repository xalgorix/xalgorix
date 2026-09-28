---
name: gcp-iam-privilege-escalation
description: GCP IAM privilege escalation — service account actAs, getAccessToken, signBlob and signJwt, serviceAccountKeys, setIamPolicy at project/folder/org levels, custom role manipulation, Cloud Build and Compute with stronger SAs, Functions and Cloud Run deployment abuse with inherited-role awareness
intent: offensive
assessment_mode: credentialed
provider:
  - gcp
---

# GCP IAM Privilege Escalation

## Purpose
Prove GCP escalation from a starting principal to a higher-privilege identity or effective permission — typically service-account impersonation or policy modification — with the previously unavailable action demonstrated. A broad role detected is never equivalent to successful escalation.

## Entry Conditions
- Validated GCP credential with an effective-permission map (`gcp-cloud-pentesting` steps 1–2)
- Runtime authorization for state-changing operations

## Attack Model

```text
starting identity
→ escalation primitive (actAs / token mint / policy set / deploy with SA)
→ higher-priv identity or effective permission
→ previously unavailable cloud action SUCCEEDS
→ report
```

## Methodology

### Family 1 — Service Account Impersonation
```bash
# roles/iam.serviceAccountUser (actAs) over a target SA = act as it everywhere:
gcloud auth print-access-token --impersonate-service-account=<target-sa>   # THE proof — then use the token
# roles/iam.serviceAccountTokenCreator: mint tokens for the SA without actAs:
gcloud iam service-accounts sign-jwt --iam-account <sa> ... 
gcloud iam service-accounts sign-blob --iam-account <sa> ...
# Check who holds these over high-value SAs (default compute/editor SAs!):
gcloud iam service-accounts get-iam-policy <sa-email> --flatten="bindings[].members"
```

### Family 2 — Key Creation
```bash
# iam.serviceAccountKeys.create on a privileged SA = durable takeover:
gcloud iam service-accounts keys create key.json --iam-account=<target-sa>
# Service Account Key Admin on the project = keys for every SA in it
```

### Family 3 — Policy Modification
```bash
# resourcemanager.projects.setIamPolicy (or folder/org levels — inherited DOWN):
gcloud projects add-iam-policy-binding <project> --member="serviceAccount:<your-sa>" --role="roles/owner"
# iam.serviceAccounts.setIamPolicy on an SA = grant yourself actAs/tokenCreator on it
# Custom-role manipulation (iam.roles.update/create) = sneak privileges past predefined-role review
```

### Family 4 — Execution with Stronger SAs
```text
actAs + Cloud Run deploy       → a service running as a privileged SA
actAs + Cloud Functions create
actAs + Compute instance create → instance with an attached privileged SA; then metadata-token
actAs + Cloud Build trigger      → build executes as the build SA (historically roles/editor)
```

## Inheritance Rule
Before claiming a grant: resolve org → folder → project → resource levels. A broad binding at the org level makes a "low-privilege-looking" project principal far more powerful than the project policy shows; conversely, org policies (constraints like disabling SA key creation) can silently block your primitive — check `gcloud resource-manager org-policies list` when a primitive fails unexpectedly.

## Evidence Contract

```text
escalation candidate (actAs/tokenCreator/setIamPolicy held)
→ inheritance + org-policy constraints resolved
→ impersonation/policy/deployment performed (within runtime policy)
→ higher-priv token obtained or binding active
→ previously unavailable action SUCCEEDS (object in another project, secret accessed, role assigned)
→ restore created state (delete created keys/bindings/functions)
→ report
```

**NOT evidence**: `roles/editor` observed on the default SA without a live impersonated action, tool output (CSPM/PMapper analogues) without verification, `TestIamPermissions` claims without a performed action, a binding added but never exercised

## Common Misses
- TokenCreator vs actAs confusion (different primitive, same impact class)
- Folder/org-level actAs grants (invisible at project policy level)
- Default compute SAs (`<project>-compute@developer.gserviceaccount.com`) as targets
- Org-policy constraints blocking key creation (treated as "no permission" instead of "blocked primitive")
- Cloud Build service accounts as the escalation vehicle
- signBlob/signJwt enabling service-to-service auth forgery (KMS/JWT signing chains)

## False Positives / Non-Findings
- actAs on SAs with no meaningful privileges
- Grants scoped to resources you already control
- Key creation disabled by org policy (hardening observation, not a finding)
- Expired/stale bindings from deleted principals

## Xalgorix Tool Strategy
- `terminal_execute` with gcloud for every primitive; Policy Analyzer for effective-permission hypotheses
- Ledger: candidate impersonation chains with constraint state and verified proofs
- Restore: `gcloud iam service-accounts keys delete`, `remove-iam-policy-binding`, function/service deletion

## Specialist Handoffs
- Data reached via the new identity → `cloud-secrets-data-access`, `cloud-storage-exposure-testing`
- Cross-project trust → `cloud-cross-account-tenant-trust`
- Compute instance with attached SA → metadata-token chain via `cloud-metadata-workload-identity`

## Stopping Rule
Prioritize: direct impersonation (actAs/getAccessToken) > key creation > policy modification > deployment-with-SA. Depth-first on the highest-privilege SAs (editor/owner, default compute SAs). Stop when project-admin-equivalent access is proven or the top families are constraint-blocked.