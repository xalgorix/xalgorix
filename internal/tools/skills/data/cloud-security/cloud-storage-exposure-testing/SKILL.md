---
name: cloud-storage-exposure-testing
description: Offensive storage exposure testing across AWS S3, Azure Blob/ADLS, and GCP Cloud Storage — existence, listing, read, write, overwrite, delete, ACL/policy modification, and signed-URL behavior with effective-access evidence
intent: offensive
assessment_mode:
  - blackbox
  - credentialed
provider:
  - aws
  - azure
  - gcp
---

# Cloud Storage Exposure Testing (S3 / Azure Blob / GCS)

## Purpose
Test cloud storage for unauthorized access — externally (black-box) or with credentials — proving the exact permission level obtained: existence, listing, read, write, overwrite, delete, or policy modification. Never collapse these into a single "public bucket" status.

## Entry Conditions
- Candidate bucket/container names (from `cloud-attack-surface-discovery`, recon, or credentialed enumeration)
- Anonymous context always; authenticated-low-priv and discovered-credential contexts where available
- Credentialed mode: `s3:GetBucketPolicy`-class read access to evaluate effective configuration

## Discovery Signals
- Bucket hostnames in JS/CNAME/error messages
- Company/domain/project naming seeds (`<company>-backups`, `<domain>-assets`, `<project>-staging`)
- Presigned URLs (scope, expiry, and signature reveal bucket + often account ID)
- Credentialed: `s3api list-buckets`, storage account keys, `gsutil ls`

## Attack Model

Separate the permission levels and prove each independently:

```text
existence      — does the resource exist at all?
listing        — can the caller enumerate object keys?
read           — can the caller retrieve object contents?
write          — can the caller create objects?
overwrite      — can the caller replace existing objects?
delete         — can the caller remove objects?
ACL/policy mod — can the caller rewrite the access policy itself?
signed URLs    — can the caller mint/extend/abuse presigned access?
cross-account  — can another tenant/account principal reach it?
```

## Methodology

### Step 1: Existence and Anonymous Baseline (AWS)
```bash
# Existence: 404 vs AccessDenied (a 403 on anonymous GET means the bucket EXISTS)
curl -sk -o /dev/null -w "%{http_code}\n" https://s3.amazonaws.com/<bucket>          # 404=absent, 403=exists-protected
curl -sk "https://s3.amazonaws.com/<bucket>/" | head -c 200                          # 200 = anonymous LISTING
curl -sk "https://s3.amazonaws.com/<bucket>/known-object-key"                        # object-level read
aws s3 ls s3://<bucket> --no-sign-request                                            # anonymous listing via CLI
```

### Step 2: Effective Access (not policy text)
A policy containing `"Principal": "*"` is only a CANDIDATE. Effective access can still be denied by:
- Block Public Access (account and bucket level)
- policy conditions (`aws:SourceIp`, `s3:authType-*`)
- access point policies
- object-level ACLs
- VPC endpoint policies
- organizational SCPs

Verify the account/bucket configuration directly when credentialed:
```bash
aws s3api get-public-access-block --bucket <bucket>     # and account level
aws s3api get-bucket-policy --bucket <bucket>
```
Prove it: actually list and read. Conversely, `allAuthenticatedUsers` (GCS `allUsers`/`allAuthenticatedUsers`, Azure public container/SAS) is a candidate until a real object is retrieved with the anonymous/authenticated-low context.

### Step 3: Write/Delete Probes (where scope permits)
```bash
# Create a uniquely-named test object — never touch existing data
echo "xalgorix-probe-$(date +%s)" > /tmp/probe.txt
aws s3 cp /tmp/probe.txt s3://<bucket>/xalgorix-probe-test.txt --no-sign-request
aws s3api put-object --bucket <bucket> --key xalgorix-probe-test.txt --body /tmp/probe.txt --no-sign-request
# Overwrite/delete probes only with explicit runtime authorization for state changes
```

### Step 4: Azure Blob
```bash
# Public access: container-level "blob"/"container" publicAccess
curl -sk -o /dev/null -w "%{http_code}\n" "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"
# SAS tokens: check expiry, permissions (sp=rwdl...), IP scope; try extension/abuse
# Credentialed: az storage container list --account-name <account>
```

### Step 5: GCP Cloud Storage
```bash
curl -sk "https://storage.googleapis.com/<bucket>" | head -c 200            # XML API anonymous listing
gsutil ls -L gs://<bucket>                                                   # if authenticated
# TestIamPermissions is a claim, not proof — follow with actual ls/cp
# Run enumeration BOTH anonymous AND with any Google account (allAuthenticatedUsers grants)
```

### Step 6: Credentialed Configuration Review
In credentialed mode, configuration evidence can itself be a finding when the assessment asks for misconfigurations: public policies without BPA, wildcard principals, over-broad SAS, disabled soft-delete on sensitive data. Distinguish these as configuration findings, not exploit-proven findings.

## Evidence Contract

```text
candidate bucket
→ anonymous request
→ actual private object returned / written / deleted (concrete object name + content class)
→ sensitivity/impact assessment (what data, how sensitive, how much)
→ report at the proven permission level
```

A bucket existing is not a vulnerability. A wildcard policy is not proof. Read/list/write must each be demonstrated. A write is only a finding with the probe object name recorded.

**NOT evidence**: 403 on anonymous GET (existence only), policy text with `Principal:"*"` (candidate), `allAuthenticatedUsers` mention (candidate), tool output (CloudStorage scan) without retrieval

## Common Misses
- Object-level ACLs granting read on a public-in-policy bucket (or vice versa)
- Access points (S3) with policies differing from the bucket policy
- Presigned URL leakage in JS/referers — often grants write or higher
- Azure SAS tokens with excessive permissions/long expiry
- GCS buckets granting `allAuthenticatedUsers` — missed when only anonymous tests ran
- Snapshot/AMI sharing (adjacent storage surfaces): `restorable-by-user-ids all` in credentialed mode
- Region-specific endpoints (s3.eu-west-1.amazonaws.com) when the global endpoint 404s

## False Positives / Non-Findings
- Public-by-design assets (marketing images, public releases) with no sensitive objects
- Existence-only signals (403s)
- Expired presigned URLs
- Buckets belonging to third parties that merely share a naming seed

## Xalgorix Tool Strategy
- `terminal_execute` with aws CLI/az/gsutil/curl for direct evidence
- Python for seed-based candidate generation (bounded wordlists)
- GCPBucketBrute optional for anonymous+authenticated enumeration with custom keywords
- Every confirmed level → ledger with object name + sensitivity

## Specialist Handoffs
- Credentials found in bucket contents → `cloud-credential-abuse`
- Bucket serving a web app / origin for CDN → `cloud-attack-surface-discovery` attack model entry
- Credentialed configuration-only findings → configuration assessment mode section of the provider skill

## Stopping Rule
For each candidate: prove existence, then anonymous listing/read, then (where authorized) write. Stop candidate generation once target-derived seeds are exhausted and no new high-confidence names emerge. Do not enumerate unlimited global namespaces.