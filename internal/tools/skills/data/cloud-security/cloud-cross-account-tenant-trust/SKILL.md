---
name: cloud-cross-account-tenant-trust
description: Cross-account and cross-tenant trust testing — AWS role trust and resource policies, Azure cross-tenant applications and federated credentials, GCP IAM inheritance and service-account impersonation, requiring full trust-edge verification before claiming an attack path
intent: offensive
assessment_mode:
  - blackbox
  - credentialed
provider:
  - aws
  - azure
  - gcp
---

# Cloud Cross-Account / Cross-Tenant Trust

## Purpose
Test trust boundaries between identities, accounts, tenants, and projects: whether an attacker-reachable principal can cross a trust edge into a target with meaningful new privileges or resources.

## Entry Conditions
- A principal under test (attacker identity, or the target's identity exposed via credential discovery)
- Trust-edge candidates: role trust policies, resource policies with cross-account principals, cross-tenant app registrations, federated credentials, cross-project IAM grants

## Attack Model

```text
source principal
→ trust edge (role trust / resource policy / federation / org grant)
→ conditions (ExternalId, MFA, org-id, IP, audience)
→ target principal/resource
→ effective action actually performed
→ report only the verified path
```

## Methodology

### AWS — Role Trust
```bash
aws iam get-role --role-name <role> --query "Role.AssumeRolePolicyDocument"
# A trust policy with Principal: arn:aws:iam::<account>:root is only a CANDIDATE:
# it delegates to the whole account, not to you. You also need sts:AssumeRole in YOUR
# identity policy, and every condition satisfied (ExternalId, MFA, aws:SourceOrgID...).
aws sts assume-role --role-arn <arn> --role-session-name xalgorix-test --external-id <id-if-known>
```

### AWS — Resource Policies
S3, KMS, SNS/SQS, ECR, Lambda, and secrets all support resource policies that can grant external principals:
```bash
aws s3api get-bucket-policy --bucket <b>
aws ecr get-repository-policy --repository-name <r>
aws kms get-key-policy --key-id <k> --policy-name default
# Then actually perform the cross-account action from the source context
```
Snapshot/AMI/RDS sharing is an adjacent surface: `describe-snapshots --owner <self>` and check `restorableByUserIds` for foreign accounts (and reverse: what the target shares outward).

### Azure — Cross-Tenant
```text
- multi-tenant app registrations: consent from a foreign tenant grants the app rights there
- B2B/external identities and their effective role assignments
- federated identity credentials on apps/service principals: an issuer/subject match
  lets the holder mint tokens AS the app — verify by requesting a token with the
  matching issuer and testing app roles
- cross-tenant service principals with privileged Graph app roles
```

### GCP — Cross-Project and Federation
```text
- org/folder/project IAM inheritance: a grant at org level flows down — enumerate the
  effective policy at each level (gcloud projects get-iam-policy, --flatten)
- external principals / allUsers / allAuthenticatedUsers in bindings
- workforce/workload identity federation configs: attribute-condition bypasses
- service-account impersonation chains: actAs/getAccessToken across projects
```

## Classification Rules (high-value false-positive traps)

- `Principal: <account>:root` + missing `sts:ExternalId` = CANDIDATE. Missing ExternalId is security-relevant in third-party delegation models but is not universal proof. The full chain (identity-side permission + trust conditions + successful assumption + usable credentials + meaningful privilege gain) makes it a finding.
- `Principal: "*"` in a resource policy = candidate until effective access is demonstrated (conditions, BPA, org controls can still block).
- A trust edge into an account holding nothing valuable is not an impact finding — record the path, evaluate the target's value.

## Evidence Contract

```text
trust candidate (policy/registration/federation observed)
→ source context established
→ conditions satisfied
→ assumption/authorization call SUCCEEDS (usable credentials/token obtained)
→ meaningful resource access or privilege in the target context performed
→ report the complete path
```

**NOT evidence**: trust-policy text alone, a missing ExternalId, PMapper/Pacu graph edges (hypothesis), cross-tenant app existing without demonstrated consent/token abuse

## Common Misses
- Identity-side permission never checked (trust allows, identity policy denies — no path)
- Condition keys (org-id, SourceArn, MFA) never enumerated
- Reverse direction: what the TARGET's accounts grant to the world (their outbound edges)
- Azure federated credentials on applications (issuer/subject confusion)
- GCP org-level grants inherited invisibly into every project

## False Positives / Non-Findings
- Trust policies that only reference the same account
- Resource policies granting access to a specific external principal you do not control
- Conditions that genuinely block your context (org-id mismatch)
- Expired federation configurations

## Xalgorix Tool Strategy
- `terminal_execute` with aws/az/gcloud for policy reads and assumption calls
- PMapper/CloudFox optional for graph hypothesis generation — every edge verified manually
- Ledger: trust edges with source, edge type, conditions, target, verified state

## Specialist Handoffs
- Escalation inside the reached account → provider privilege-escalation skills
- Storage reached via trust → `cloud-storage-exposure-testing`
- Trust edges discovered in black-box mode → `cloud-attack-surface-discovery` for candidate expansion

## Stopping Rule
Verify the full chain for the top-value trust candidates (privileged roles, resource-rich accounts, Graph-privileged apps). Do not enumerate every trust policy in an org when one verified privileged path already proves the class.