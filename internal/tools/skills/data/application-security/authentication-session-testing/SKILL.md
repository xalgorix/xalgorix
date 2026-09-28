---
name: authentication-session-testing
description: Black-box testing of the full authentication and session lifecycle - registration, login, MFA,
  password reset, recovery, email change, logout, refresh, device trust - and session token handling including
  fixation, invalidation, replay, and cross-context binding.
domain: cybersecurity
subdomain: application-security
tags:
- authentication
- session-management
- session-fixation
- mfa-bypass
- account-recovery
- owasp
version: '2.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
intent: offensive
phase: application-testing
blackbox: true
---

# Authentication and Session Testing

## Purpose

Test the entire account and session lifecycle as a state machine, not just login. Every lifecycle transition (register, verify, login, MFA, reset, recovery, email change, role change, logout) is a boundary where revocation, binding, or downgrade logic is forgotten.

## Entry Conditions

- The target has any account lifecycle: signup, login, password reset, MFA, profile/email change, or log-out-other-sessions features
- You hold at least one valid account (ideally two, plus control of a second email address)

## Step 0: Find the REAL Session Token

Apps set many cookies (analytics, CSRF, consent). Delete cookies one at a time and re-request a protected page - the one whose removal logs you out is the session token. Test only that one for the flaws below.

## Session Lifecycle Matrix

Capture a valid session token, then perform each lifecycle event in a SEPARATE session and replay the old token against a protected route. Record status + body differential for each:

| Event | Question | Evidence to capture |
|---|---|---|
| Logout | is the old token dead server-side? | old cookie replay after logout |
| Password change | are other sessions revoked? | old session still valid after change |
| Password reset | does reset invalidate all sessions? | old session after reset completes |
| MFA change / enrollment | are sessions re-verified? | old session after MFA enrollment |
| Role change (up or down) | does privilege apply to existing sessions? | old session reaching admin route after downgrade |
| Account disable / deletion | immediate revocation? | old session after admin-side disable |
| Email change | does notification + re-verification occur? | old session after email change |

A stale token still working after logout is a server-side revocation failure (critical for stolen-session scenarios) - prove it with a state-changing request, not a cached GET.

## Session Token Handling

- Fixation: record the cookie value BEFORE authenticating; log in; compare. If the identifier does not rotate on privilege elevation, a pre-set cookie survives login and can be fixed onto a victim.
- Replay across context: replay the token from a different IP / User-Agent / device fingerprint. Accepted with no re-auth or alert = unbound session.
- Parallel sessions: same account from two machines - both stay valid with no notification is often in-scope for sensitive apps.
- Client-side session data: base64/JSON-decode cookies. If user=, role=, email=, isAdmin= live inside, tamper with another user value and replay - the server may trust it blindly.
- Entropy: flip one byte at a time to find which segment is actually validated; a short validated segment is brute-forceable. Run Sequencer-style randomness analysis over thousands of tokens when feasible.
- Cookie hardening: HttpOnly, Secure, SameSite, Domain scope, Max-Age. Missing flags are hardening observations - not findings alone; pair them with a demonstrated attack (XSS token theft, subdomain leak) before reporting.
- Leakage: session value in URLs, Referer headers to external hosts, analytics/error beacons.

## Account Lifecycle Abuse

### Registration
- Duplicate-account evasion: user+1@domain tricks, unicode/case tricks - free-trial and referral limits assume uniqueness
- Role/tenant fields accepted at registration ("role":"admin", "tenant_id") - mass-assignment lead; hand off to the mass-assignment specialist
- Verification optional? Register, then immediately access verified-only functions

### Login
- Error differential: valid-user/wrong-password vs invalid-user - enumerate usernames from response shape, timing, or reset-flow behavior
- Authentication downgrade: does a legacy route accept password-only when the modern flow requires MFA?

### MFA bypass routes
- Alternate endpoint/API version/mobile route that skips the MFA step
- Remember-device logic: forge/steal the remember cookie; does it carry identity?
- Recovery flow: is recovery MFA-gated or weaker-gated than login?
- Old session reuse: complete MFA in session A, replay the pre-MFA session B token
- Direct post-auth route: hit the post-MFA landing endpoint immediately after password-only login

### Password reset / recovery
- Token binding: use victim email + attacker token; does reset apply to the victim account?
- Account association: reset link for user@x used against USER@X or user+tag@x
- Token reuse after consumption; expiration enforcement; token in URL leaking via Referer
- Host-header poisoning of reset emails (hand off to host-header-attacks specialist)
- Identifier normalization tricks: victim+tag@domain, trailing dot - does the reset go to the victim account but a mailbox you control?

### Email change / verification
- Change email to one you control WITHOUT re-verification, then trigger password reset - full ATO chain; capture both steps
- Verification link reuse across accounts

## Methodology

```text
map the lifecycle events the app exposes
-> capture a valid session token (baseline)
-> trigger each lifecycle event, replay the OLD token
-> record the differential (dead vs alive)
-> for each alive-after-event case, prove a state change or protected read
-> report with both request pairs attached
```

## Evidence Contract

Not enough: old cookie returned 200 on GET /profile (may be cached or idempotent read).
Good proof: the stale session performs an authenticated state change (update profile, read private data never exposed to anonymous) - request/response pair attached, lifecycle event timestamped.

Not enough: reset token appeared reusable. Good proof: the same token changes the password a second time after consumption, with both responses captured.

## Common Misses

- Testing only the primary web flow: mobile/legacy/GraphQL auth routes frequently skip MFA or rate limits
- Reset flows tested only with the account own email - cross-account token binding is the critical test
- Never testing session behavior across role changes (admin -> user downgrade with admin session retained)
- Ignoring the logout endpoint entirely: logout that only clears the client cookie is a server-side revocation failure

## False Positives

- 200 from a cached/idempotent GET with a dead session - always use a state-changing or identity-revealing request to confirm liveness
- Secure/HttpOnly absence reported as vulnerability without a demonstrated theft path
- Login error messages reported as user enumeration when the differential is not reproducible (same bytes, same timing class)

## Xalgorix Tool Strategy

- browser_action to drive real lifecycle flows (register, login, MFA, logout) and capture the traffic
- http_request to replay tokens outside the browser across IP/UA contexts
- authz_matrix for cross-identity token/context differentials in one call
- record_hypothesis per lifecycle event; add_hypothesis_evidence with both request pairs
- Deterministic verifiers once a class signal appears (verify_csrf, verify_timing for enumeration)

## When to Load a Specialist Skill

- JWT-based tokens -> jwt-security-testing (api-security)
- OAuth/OIDC flows -> oauth-oidc-security; SAML -> exploiting-saml-authentication-flaws
- Forced browsing after auth bypass -> bypassing-authentication-with-forced-browsing
- Reset email poisoning -> host-header-attacks; 2FA-specific deep-dives -> 2fa-mfa-bypass

## Stopping Rule

Stop lifecycle testing when: every lifecycle event the app exposes has its before/after token differential recorded, the recovery flow has been exercised cross-account at least once, and no new auth route (mobile/legacy/GraphQL) has appeared for two consecutive discovery passes. Report proven revocation/binding failures; record hardening observations as low-priority notes.

## Handoffs

- application-attack-surface-modeling - the role/state model feeding this skill
- authorization-testing - what the session is allowed to do after auth
- workflow-state-machine-testing - multi-step verification/approval flows
