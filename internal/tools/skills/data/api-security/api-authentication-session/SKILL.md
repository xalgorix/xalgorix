---
name: api-authentication-session
description: API authentication and session testing — unauthenticated endpoint exposure, token lifecycle (logout revocation, refresh rotation, expiry), credential flows, password policy, account enumeration, and API key weaknesses (OWASP API2)
intent: offensive
protocol: rest
---

# API Authentication & Session Testing (OWASP API2)

## Purpose
Test API authentication mechanisms for bypasses: endpoints reachable without valid credentials, tokens that outlive their lifecycle, credential flows that leak or over-trust, and session handling that enables account takeover.

JWT/OIDC-specific token forgery belongs to jwt-security-testing and oauth-oidc-security.

## Preconditions
- At least one valid account/session
- A mapped API surface (endpoints, roles, auth scheme) from reconnaissance
- Auth tokens/cookies for the account under test

## Attack Surface Signals
- Bearer tokens, API keys, session cookies, basic auth, signed custom headers
- Auth-adjacent flows: login, register, password reset, MFA verify, token refresh, logout
- Endpoints that "should" require auth: profile, settings, internal status
- Tokens appearing in URLs, logs, or client-side storage

## Methodology

### Step 1: Identify the Mechanism
```bash
# What does the API advertise without credentials?
curl -sk -i "https://TARGET/api/users/me" | head -20
# Login and catalog what is issued (JWT? opaque token? cookie? refresh token?)
curl -sk -X POST "https://TARGET/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"PASS"}' | jq 'keys'
```

### Step 2: Unauthenticated Endpoint Sweep (candidate collection)
```bash
for p in users users/me admin/settings health metrics debug actuator \
  actuator/env status info version config .env internal/status; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/api/$p")
  echo "$p -> $code"
done
```
Non-401/403 responses are CANDIDATES. A finding requires the unauthenticated response to contain data or actions that should require authentication — not a 200 on a public health endpoint.

### Step 3: Token Lifecycle
```bash
# Valid after logout?
curl -sk -X POST -H "Authorization: Bearer TOKEN" "https://TARGET/api/auth/logout"
curl -sk -H "Authorization: Bearer TOKEN" "https://TARGET/api/users/me" -o /dev/null -w "%{http_code}\n"
# Refresh token rotation: is the OLD refresh token still usable after a refresh?
curl -sk -X POST "https://TARGET/api/auth/refresh" -d '{"refresh_token":"RT"}'
curl -sk -X POST "https://TARGET/api/auth/refresh" -d '{"refresh_token":"RT"}'  # replay
# Token accepted as query parameter? (leaks into logs/referrers)
curl -sk "https://TARGET/api/users/me?token=TOKEN" -o /dev/null -w "%{http_code}\n"
```
A "token valid after logout" finding requires the post-logout response to return real protected data, not just a 200.

### Step 4: Auth-Adjacent Flow Abuse
- Password reset: is the reset token single-use? guessable? does reset invalidate existing sessions?
- MFA verify: is the verify endpoint rate-limited? does it enumerate valid codes/timing?
- Register: can `role`/`email_verified`/`tenant` be set in the signup body (see api-bopla)?
- Login: response differential between valid and invalid usernames (enumeration below)

### Step 5: Account Enumeration (differential evidence required)
```bash
curl -sk -X POST "https://TARGET/api/auth/login" -d '{"username":"real@example.com","password":"wrong"}' > tmp/v.json
curl -sk -X POST "https://TARGET/api/auth/login" -d '{"username":"nobody-xyz@example.com","password":"wrong"}' > tmp/i.json
diff <(jq -S . tmp/v.json) <(jq -S . tmp/i.json)
```
A finding requires a REPRODUCIBLE differential (body, status, or consistent timing) between valid and invalid identities — the same differential must not exist between two invalid identities.

### Step 6: Credential Controls
- Password policy: register/change with weak passwords; record which are accepted
- API keys: predictable format? verified server-side or trusted by value alone? cross-service key reuse?
- Default credentials on admin/auth endpoints: confirm by receiving an authenticated session, not just 200

## Evidence Contract
An authentication finding requires ALL of:
1. Baseline: the protected resource/action denies the anonymous or invalid-credential control
2. Manipulation: the auth weakness exploited (missing check, dead token, replay, forged identity)
3. Differential: the attacker context receives protected data or completes a protected action
4. Reproducibility

**NOT evidence**: 200 on a public endpoint, missing WWW-Authenticate header alone, a token that "looks" weak, one slow response, status-code-only differences that flip on retry

## Common Misses
- Auth checked at the gateway but not the backend (direct-to-service paths)
- Permissive CORS on the auth endpoints themselves
- MFA applied at login but not on token refresh
- Session tokens accepted across services with different sensitivity
- Timing-based enumeration (measure with repeated samples, not single requests)

## False Positives / Non-Findings
- Public-by-design endpoints returning non-sensitive data
- Generic auth error messages (enumeration properly blocked)
- Logout invalidating only the browser session while token TTL is short — check actual remaining impact
- 200 responses that return the anonymous view of a resource

## Xalgorix Tool Strategy
- `http_request`/curl for precise lifecycle probes; Python for repeated timing samples
- `authz_matrix` for session-context differentials
- agentmail where password-reset/MFA email flows need inbound access

## Stopping Rule
Every auth-adjacent endpoint x lifecycle stage (issue, use, refresh, logout, expiry) x anonymous/invalid/expired/replayed contexts.

## Handoff
Report the flow, the weakness class (missing enforcement, revocation failure, rotation failure, enumeration differential), the concrete protected outcome achieved, and token details. Token-signature weaknesses go to jwt-security-testing; delegated-authorization issues to oauth-oidc-security.