---
name: cloud-attack-surface-discovery
description: Black-box discovery of a target's cloud footprint from an ordinary internet-facing domain — DNS, CNAME, headers, TLS, JavaScript, CSP, and error evidence fingerprinted to AWS, Azure, and GCP services, resources, accounts/tenants/projects, and applicable attack methodology
intent: offensive
assessment_mode: blackbox
provider:
  - aws
  - azure
  - gcp
---

# Cloud Attack Surface Discovery (Black-Box)

## Purpose
Derive a target's cloud attack model starting from only a domain or web application, using external evidence only. Output a provider/service/resource map that drives which offensive cloud skill to load next — not a "cloud detected" label.

## Entry Conditions
- An internet-facing target (domain, web app, or IP) with no cloud credentials supplied or discovered
- Reconnaissance output available (subdomains, JS, crawl data) — consume it; do not re-crawl here

## Discovery Signals

| Source | What to extract |
|---|---|
| DNS / CNAME | `*.amazonaws.com`, `*.cloudfront.net`, `*.azurewebsites.net`, `*.trafficmanager.net`, `*.run.app`, `*.cloudfunctions.net`, `*.firebaseapp.com`, `*.blob.core.windows.net` |
| HTTP headers | `x-amz-*`, `x-azure-*`, `Server: cloudfront`, `via: 1.1 google`, `x-served-by: cache-*` |
| TLS certificates | SANs revealing internal hostnames, `*.cloudapp.azure.com`, load-balancer pool names |
| JavaScript / source maps | API endpoints, signed-URL generation, Cognito/AAD/Google client IDs, SDK usage |
| CSP / security headers | Allowed origins revealing S3/Azure/GCS buckets, API hosts |
| Static/image/upload URLs | Bucket hostnames, CDN origins, presigned URL patterns |
| Redirect destinations | OAuth flows revealing tenant IDs, app registrations |
| Error messages | Provider error XML/JSON (S3 `AccessDenied`, Azure `AuthenticationFailed`, GCP quota errors) exposing bucket/account names |
| robots/sitemaps/manifests | Hidden paths to API/storage resources |

## Provider Fingerprints

### AWS
`amazonaws.com`, `s3.amazonaws.com` / `s3-website-*`, `execute-api.*.amazonaws.com` (API Gateway), `*.lambda-url.*.on.aws` (Function URLs), `cloudfront.net`, `elasticbeanstalk.com`, `*.elb.amazonaws.com`, `amplifyapp.com`, Cognito pool IDs (`us-east-1_XXXX`, `aws.cognito.*` in JS), ECR public galleries, App Runner domains. Derive the **12-digit account ID** where possible (S3 ARNs in presigned URLs, Lambda `x-amz-invocation-*` errors, resource policies).

### Azure
`azurewebsites.net` (App Service/Functions), `blob.core.windows.net` / `dfs.core.windows.net`, `azureedge.net`, `trafficmanager.net`, `cloudapp.azure.com`, `azure-api.net` (APIM), `*.vault.azure.net` (Key Vault). Derive the **tenant ID** from OIDC metadata (`https://login.microsoftonline.com/<tenant>/.well-known/openid-configuration` — responds for valid tenants), app registration client IDs in JS.

### GCP
`storage.googleapis.com`, `*.appspot.com` (App Engine/GCS), `run.app` (Cloud Run), `*.cloudfunctions.net`, `googleapis.com` endpoints, `firebaseapp.com` / Firebase config objects in JS, `*.web.app`. Derive the **project ID** from bucket names (`gs://<project>-...`), Firebase config, or API URLs.

## Attack Model Output

For every discovered signal, record in the hypothesis ledger:

```text
target hostname
→ provider (aws/azure/gcp)
→ cloud service (S3 / CloudFront / API Gateway / Blob / App Service / Cloud Run / ...)
→ candidate account ID / tenant ID / project ID
→ trust boundary implied (public resource? shared identity? delegated API?)
→ applicable offensive skill (cloud-storage-exposure-testing, serverless-cloud-security, cloud-credential-abuse, provider pentest skill)
→ next concrete probe
```

Fingerprints are reconnaissance signals, NOT vulnerabilities. A CloudFront header alone is never a finding.

## Public Resource Discovery

With naming seeds from the target (company, domain, project names), probe for externally reachable resources — do not brute-force enormous global namespaces blindly:

- AWS: S3 buckets (`<company>-*`, `<domain>-*`, `assets-*`, `backups-*`), CloudFront distribution origins, API Gateway stages, Lambda Function URLs, Cognito pool domains, ECR public repos, publicly shared snapshots/AMIs (`describe-snapshots --restorable-by-user-ids all` is credentialed; anonymous listing via error differentials)
- Azure: blob containers (`https://<seed>.blob.core.windows.net/<container>`), App Service slots, API Management gateways, OAuth metadata for app registrations
- GCP: GCS buckets (`gs://<seed>*`), Firebase projects, public Cloud Run/Functions URLs, service account emails leaked in configuration

Use target-derived seeds first; widen wordlists only when seeds are exhausted.

## Methodology

### Step 1: Collect External Evidence
```bash
dig +short CNAME target.com www.target.com cdn.target.com
dig +short TXT target.com            # sometimes reveals verification/infra hints
curl -sk -D- https://target.com -o /dev/null | grep -iE "x-amz|x-azure|server|via"
curl -sk https://target.com | grep -oE "https?://[a-zA-Z0-9.-]+\.(amazonaws|cloudfront|azurewebsites|blob\.core|run\.app|cloudfunctions|storage\.googleapis)[a-zA-Z0-9.-]*" | sort -u
```

### Step 2: Expand via JavaScript and Crawl Data
```bash
# Pull all JS from recon output, extract cloud endpoints, client IDs, bucket names
grep -ohE "(cognito-idp\.[a-z0-9-]+\.amazonaws\.com|accounts\.google\.com/o/oauth2|login\.microsoftonline\.com/[a-f0-9-]{36})" js/*.js | sort -u
grep -ohE "gs://[a-z0-9-]+|https://[a-z0-9-]+\.blob\.core\.windows\.net/[^\"']*" js/*.js | sort -u
```

### Step 3: Resolve Identity Anchors
- AWS account ID: from presigned URLs (`X-Amz-Credential` contains `AKIA...`-scoped account paths, S3 ARNs), Lambda error leaks
- Azure tenant ID: enumerate via `login.microsoftonline.com/<domain>` — `GET /{domain}/.well-known/openid-configuration` returns `tenantid` for the domain's tenant; common tenant lookups via `https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration`
- GCP project ID: bucket naming, Firebase `authDomain`/`projectId` in JS, `X-Goog-` header responses

### Step 4: Probe Candidate Resources Anonymously
For each candidate resource: existence check → anonymous access check → hand off to `cloud-storage-exposure-testing` (storage), `serverless-cloud-security` (functions), or the provider pentest skill (everything else). Record every 401/403-vs-200 differential — existence is a candidate signal.

### Step 5: Chain into Application Primitives
Where the web app has SSRF/file-read/injection primitives, chain into `cloud-metadata-workload-identity`. Where credentials appear in JS, configs, or source maps, chain into `cloud-credential-abuse`.

## Evidence Contract
- A fingerprint is reconnaissance context — record it in the ledger, never report as a vulnerability
- A candidate resource (bucket, function, API) is a finding only after `cloud-storage-exposure-testing` / `serverless-cloud-security` demonstrates unauthorized access
- Identity anchors (account/tenant/project IDs) are attack context that unlock deeper enumeration

**NOT evidence**: "AWS detected", a CNAME to cloudfront.net, a TLS SAN, a public DNS record, a 403 from a bucket (candidate, not confirmed)

## Common Misses
- CNAME chains (two or more hops) not followed to the final origin
- JS bundles never downloaded/grepped — most client IDs and bucket names live there
- Source maps not fetched (often exposed in production)
- Azure tenant resolved via OpenID metadata never attempted
- Mobile app configs / API config endpoints skipped
- Error-message account ID leaks (S3 presign scope, Lambda invocation errors) not parsed

## False Positives / Non-Findings
- Third-party SaaS on the same cloud provider (e.g., a target using a vendor's cloud-hosted page is not the target's cloud footprint)
- CDN usage alone with no reachable origin
- Presigned URLs that are correctly scoped and expired
- Public marketing content served from a bucket with no sensitive objects

## Xalgorix Tool Strategy
- `terminal_execute` with dig/curl/grep for evidence collection; Python for bulk JS parsing
- Reconnaissance output (subdomain/JS/crawl corpora) as input
- Ledger entries for each discovered resource with the attack-model fields above

## Specialist Handoffs
- Storage candidates → `cloud-storage-exposure-testing`
- Function/API candidates → `serverless-cloud-security`, `api-security` skills
- SSRF/file-read primitives → `cloud-metadata-workload-identity`
- Discovered credentials → `cloud-credential-abuse`
- Trust edges / shared accounts → `cloud-cross-account-tenant-trust`
- Kubernetes boundary (EKS/AKS/GKE control planes) → provider pentest skill, then `container-security` for internals

## Stopping Rule
Stop broad enumeration once the provider/service mapping is stable, all target-associated resources found via seeds are tested, and no new high-confidence naming seeds have emerged in the last N probes. Depth-first on the strongest signal (an accessible resource beats ten 403 candidates).