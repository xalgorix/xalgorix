---
name: aws-iam-privilege-escalation
description: AWS IAM privilege escalation — CreatePolicyVersion, AttachUserPolicy, PutRolePolicy, PassRole with Lambda/EC2/Glue/SageMaker/CloudFormation/SSM, role assumption, trust-policy and resource-policy abuse, resolving boundaries/SCPs before proving the formerly denied action
intent: offensive
assessment_mode: credentialed
provider:
  - aws
---

# AWS IAM Privilege Escalation

## Purpose
Prove privilege escalation in AWS: from the current principal's permissions to a higher-privilege identity, resolving permission boundaries, SCPs, and conditions before claiming the path — then demonstrating the formerly denied action.

## Entry Conditions
- Valid low-privilege AWS credentials with an enumerated permission map (`aws-cloud-pentesting` step 1)
- Runtime authorization for state-changing operations (policy versions, role assumption, service execution) — this skill exercises them

## Attack Model

```text
baseline: denied action A
→ escalation primitive (policy modify / pass role / assume / service exec)
→ changed identity or effective permission
→ action A now SUCCEEDS
→ report (restore modified state)
```
Tool output (Pacu `iam__privesc_scan`, PMapper edge, CloudFox) is a HYPOTHESIS. Resolve it into proof.

## Methodology

### Priority Order (depth-first on strong signals)
1. Direct policy modification
2. Role assumption
3. PassRole + service execution
4. Credential creation
5. Data access (if the goal is data, not admin)
6. Indirect/service-specific escalation

### Family 1 — Direct Policy Modification
```bash
# iam:CreatePolicyVersion (managed policies cap at 5 versions)
aws iam create-policy-version --policy-arn <arn> --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' --set-as-default
# iam:SetDefaultPolicyVersion (flip to an old permissive version that already exists)
aws iam set-default-policy-version --policy-arn <arn> --version-id v3
# iam:AttachUserPolicy / AttachRolePolicy / AttachGroupPolicy
aws iam attach-user-policy --user-name <u> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# iam:PutUserPolicy / PutRolePolicy / PutGroupPolicy (inline)
aws iam put-user-policy --user-name <u> --policy-name xalgorix-test --policy-document '{...}'
# PROOF: previously denied action now succeeds; record and RESTORE original state
aws iam list-users   # example: was AccessDenied before escalation
```

### Family 2 — PassRole + Service Execution
```text
iam:PassRole + lambda:CreateFunction        → function with admin role, invoke
iam:PassRole + ec2:RunInstances            → instance with admin instance profile
iam:PassRole + glue:CreateDevEndpoint      → dev endpoint, SSH creds
iam:PassRole + sagemaker:CreateNotebookInstance
iam:PassRole + cloudformation:CreateStack  → stack with admin-capable role
iam:PassRole + ssm:SendCommand / ecs:RunTask / databrew etc.
```
Scoped PassRole is the usual gate: enumerate exactly which role ARNs are passable (read the policy Resource element and conditions) before claiming the vector. Then execute the path and prove the resulting identity.

### Family 3 — Role Assumption
```bash
aws sts assume-role --role-arn <arn> --role-session-name xalgorix-test
# Requires: identity-side sts:AssumeRole AND the target trust policy allowing your principal
# AND every condition (ExternalId, MFA, SourceOrgID) satisfied
```
See `cloud-cross-account-tenant-trust` for the full trust-edge model.

### Family 4 — Credential Creation
`iam:CreateAccessKey` on a more privileged user, `iam:CreateLoginProfile` (console access), `sts:GetFederationToken`/`sts:GetSessionToken` context checks, service-specific credential issuance (CodeBuild tokens, etc.).

### Family 5 — Service-Specific Escapes
- EC2: modify instance metadata options (IMDSv2 downgrade) when `ec2:ModifyInstanceMetadataOptions` is held
- Lambda: `lambda:UpdateFunctionCode` on an existing privileged function (no PassRole needed)
- ECR/CodeBuild/other pipeline poisoning (writable artifacts → execution)
- Glue/DataPipeline/SageMaker: interactive compute with privileged roles

## Resolving the Hypothesis (where tool output dies)
For every candidate path, resolve BEFORE claiming:
- policy `Resource` scoping and condition keys
- permission boundaries (`iam:ListPolicies...` → `aws iam simulate-principal-policy` honors boundaries)
- SCPs (invisible from inside — infer from effective denials; note as constraint in the report)
- session policies (for assumed-role contexts)
- trust policy of the target role
- service control restrictions on the passed role

## Evidence Contract

```text
escalation candidate (permission held / tool edge)
→ constraint resolution (boundaries/SCPs/conditions checked)
→ escalation operation performed (within runtime policy)
→ new identity/credentials obtained (get-caller-identity recorded)
→ previously denied action now succeeds (the proof)
→ state restored where modified (delete created key/policy/function, restore default version)
→ report
```

**NOT evidence**: Pacu/PMapper output alone, `iam:PassRole` held without a usable target-role + execution service, a trust policy read but no successful assumption, `CreateFunction` returning 200 without invoking the function under the admin role

## Eventual Consistency Rule
Do NOT blind-retry every AccessDenied. Retry-on-denial is justified only in the seconds after a relevant state change (new policy version, modified trust, new role/credential you just created or observed). A static denial after enumeration-complete is a real negative.

## Common Misses
- Permission boundaries and SCPs blocking the scanner-found path
- Scoped PassRole (role restricted to specific ARNs) unenumerated
- Non-Lambda/EC2 vectors never tried (Glue, SageMaker, DataPipeline, CloudFormation, SSM)
- `lambda:UpdateFunctionCode` on existing privileged functions (no PassRole needed)
- Resource-policy escalation (S3/KMS policies granting `iam:`-adjacent influence)
- Old permissive policy versions still present (`SetDefaultPolicyVersion` to v1)

## False Positives / Non-Findings
- Escalation paths fully blocked by boundaries/SCPs (record as hardening observation, not a finding)
- PassRole to non-privileged roles only
- Trust policies that do not include your principal or conditions
- Group-policy manipulation where no group membership exists

## Xalgorix Tool Strategy
- `terminal_execute` with AWS CLI for every primitive; Pacu/PMapper/CloudFox for hypothesis generation only
- `aws iam simulate-principal-policy` for boundary-aware checks
- Ledger: candidate paths with constraint-resolution state, verified escalations with before/after proof

## Specialist Handoffs
- Trust-edge paths → `cloud-cross-account-tenant-trust`
- Data-first goals → `cloud-secrets-data-access`, `cloud-storage-exposure-testing`
- Post-escalation account domination → `aws-cloud-pentesting` step 2 re-run at higher privilege

## Stopping Rule
Prioritize direct policy modification > role assumption > PassRole/service execution > credential creation; go depth-first. Stop when admin-equivalent access is proven OR the top 3 families are constraint-resolved and blocked. Do not enumerate every theoretical escalation indefinitely.