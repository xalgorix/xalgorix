---
intent: defensive
name: detecting-suspicious-oauth-application-consent
description: Detect risky OAuth application consent grants in Azure AD / Microsoft Entra ID using Microsoft Graph API, audit
  logs, and permission analysis to identify illicit consent grant attacks.
domain: cybersecurity
subdomain: cloud-security
tags:
- OAuth
- Azure-AD
- Entra-ID
- Microsoft-Graph
- illicit-consent
- cloud-security
- application-permissions
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Detecting Suspicious OAuth Application Consent

## Overview

Illicit consent grant attacks trick users into granting excessive permissions to malicious OAuth applications in Azure AD / Microsoft Entra ID. This skill uses the Microsoft Graph API to enumerate OAuth2 permission grants, analyze application permissions for overly broad scopes, review directory audit logs for consent events, and flag high-risk applications based on publisher verification status and permission scope.


## When to Use

- When investigating security incidents that require detecting suspicious oauth application consent
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

The most dangerous grants this Graph workflow can miss:
- **`/oauth2PermissionGrants` returns only DELEGATED consent.** Application permissions (app roles) live under `servicePrincipals/{id}/appRoleAssignments` — querying only `oauth2PermissionGrants` misses app-only `Mail.Read`/`Files.ReadWrite.All`/`Directory.ReadWrite.All`, which run with no signed-in user and are the worst case.
- **`ConsentType == "AllPrincipals"` (tenant-wide admin consent)** is far higher risk than `"Principal"` (single user) — flag `AllPrincipals` explicitly rather than treating all grants equally.
- **Programmatic grants** show as `Add app role assignment to service principal` / `Add delegated permission grant` in `directoryAudits`, not just `Consent to application` — watching only the latter misses them.
- **`offline_access` scope = refresh-token persistence** — treat as high-signal even when other scopes look benign.
- Null `verifiedPublisher` isn't malicious by itself (many legit internal apps) — combine with risky scope + recent creation to cut FP.

Validate: confirm the app token actually carries `Application.Read.All` (with only `Directory.Read.All` the enumeration returns partial data and looks clean); cross-check a flagged app against the `directoryAudits` consent event to recover the granting user and IP; maintain an allowlist of approved `appId`s to suppress known-good apps.

## Prerequisites

- Azure AD / Entra ID tenant with Global Reader or Security Reader role
- Microsoft Graph API access with `Application.Read.All`, `AuditLog.Read.All`, `Directory.Read.All`
- Python 3.9+ with `msal`, `requests`
- App registration with client secret or certificate for authentication

## Steps

1. Authenticate to Microsoft Graph using MSAL client credentials flow
2. Enumerate all OAuth2 permission grants via `/oauth2PermissionGrants`
3. List service principals and their assigned application permissions
4. Query directory audit logs for `Consent to application` events
5. Flag applications with high-risk scopes (Mail.Read, Files.ReadWrite.All, etc.)
6. Check publisher verification status for each application
7. Generate risk report with remediation recommendations

## Expected Output

- JSON report listing all OAuth apps with granted permissions, risk scores, unverified publishers, and suspicious consent patterns
- Audit trail of consent grant events with user and IP details
