---
intent: defensive
name: detecting-aws-iam-privilege-escalation
description: Detect AWS IAM privilege escalation paths using boto3 and Cloudsplaining policy analysis to identify overly permissive
  policies, dangerous permission combinations, and least-privilege violations
domain: cybersecurity
subdomain: cloud-security
tags:
- aws
- iam
- privilege-escalation
- cloudsplaining
- boto3
- policy-analysis
- least-privilege
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Detecting AWS IAM Privilege Escalation

## Overview

This skill uses boto3 and Cloudsplaining-style analysis to identify IAM privilege escalation paths in AWS accounts. It downloads the account authorization details, analyzes each policy for dangerous permission combinations (iam:PassRole + lambda:CreateFunction, iam:CreatePolicyVersion, sts:AssumeRole), and flags policies that violate least-privilege principles.


## When to Use

- When investigating security incidents that require detecting aws iam privilege escalation
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **`GetAccountAuthorizationDetails` doesn't show the whole picture:** it returns attached/inline/group policies but **not** permission boundaries, SCPs, session policies, or resource-based policies. A flagged path may actually be blocked by a boundary/SCP (false positive), or a real escalation may be *enabled* by a resource policy (e.g., a role's trust policy or an S3/KMS policy) you never parsed (false negative). Reconcile against the boundary and trust policy before reporting.
- **Non-default policy versions and inheritance:** check the policy's **default** version (attackers stage admin in a non-default version via `iam:CreatePolicyVersion`/`SetDefaultPolicyVersion`), and expand group-inherited permissions. `NotAction`/`Deny` statements and `Condition` keys (`aws:PrincipalTag`, MFA) are ignored by naive substring matching.
- **Privesc combos beyond the well-known ones:** `iam:PutUserPolicy`, `iam:AttachGroupPolicy`, `iam:UpdateAssumeRolePolicy`, and `iam:PassRole` paired with `glue`/`cloudformation`/`datapipeline`/`sagemaker`/`codebuild` create functions, plus `ssm:SendCommand` on instances bearing admin instance profiles.
- **Validate the path is real:** confirm with `aws iam simulate-principal-policy --policy-source-arn … --action-names iam:AttachUserPolicy …` (it honors boundaries/SCPs), or actually exercise the chain in an isolated test account — don't report an escalation that a boundary silently denies.

## Prerequisites

- Python 3.8+ with boto3 library
- AWS credentials with IAM read-only access (iam:GetAccountAuthorizationDetails)
- Optional: cloudsplaining Python package for HTML report generation

## Steps

1. **Download IAM Authorization Details** — Call iam:GetAccountAuthorizationDetails to retrieve all users, groups, roles, and policies
2. **Analyze Policies for Privilege Escalation** — Check each policy for known escalation permission combinations
3. **Identify Wildcard Resource Policies** — Flag policies using Resource: "*" with dangerous actions
4. **Map Principal-to-Policy Relationships** — Build a graph of which principals can access which escalation paths
5. **Score and Prioritize Findings** — Rank findings by severity based on escalation vector type
6. **Generate Report** — Produce structured JSON report with remediation guidance

## Expected Output

- JSON report of privilege escalation findings with severity scores
- List of dangerous permission combinations per principal
- Wildcard resource policy audit results
- Remediation recommendations for each finding
