---
name: workflow-state-machine-testing
description: Treat multi-step application flows as state machines and abuse them - step skipping, step replay,
  reverse ordering, cross-session and cross-account token reuse, stale-state replay, and alternate-endpoint
  state checks across web, mobile, legacy, and GraphQL routes.
domain: cybersecurity
subdomain: application-security
tags:
- workflow-testing
- state-machine
- step-bypass
- token-reuse
- stale-state
- blackbox
version: '2.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
intent: offensive
phase: application-testing
blackbox: true
---

# Workflow / State-Machine Testing

## Purpose

Registration, verification, password reset, MFA enrollment, checkout, refund, KYC, approval, invite, subscription, file import, moderation, publishing, ticket handling - every multi-step flow is a state machine. Implementations enforce the HAPPY ORDER on the client but frequently trust each server-side step in isolation. This skill systematically abuses the machine: wrong order, repeated steps, borrowed tokens, stale states, alternate endpoints.

## Entry Conditions

- A flow with 2+ sequential steps is identified, where a later step should be unreachable without an earlier one
- Step transitions are observable (tokens, status fields, changed responses, redirected routes)

## Step 1: Map the Machine

For the target flow, record every step as: trigger request, resulting state marker (token, status field, cookie, response shape), and what the NEXT step expects. State markers hide in: URL tokens, hidden form fields, JSON status fields ("verified": false, "stage": 2), session attributes, and client-side route guards in JS bundles (which reveal the EXPECTED rules the backend may not enforce).

## The Six Abuses

### 1. Step skipping

```text
intended:  1 -> 2 -> 3 -> 4
try:       1 -> 4          (and: nothing -> 4)
```
Call the terminal step directly. Examples: access the dashboard with an unverified account; confirm an order without payment; hit the post-MFA landing route after password-only login; grant access without the approval step; publish without moderation.

### 2. Step replay

```text
1 -> 2 -> 3, then replay 3 (or 2) again
```
One-time actions that can repeat: coupon redemption, vote, verification, password reset, refund. Replay the exact captured request of the completed step.

### 3. Reverse ordering

Call step 3 before step 2 (with markers fabricated or borrowed). Servers that check "is the token valid" but not "is the flow in the right stage" accept out-of-order transitions.

### 4. Cross-session performance

Perform step 1-2 in session/account A, then step 3 in session/account B. Session-bound state checks (flow stored on the session object) frequently break when the step arrives from a different session with the same token or id.

### 5. Cross-account token reuse

Use one identity tokens against another: verification links, reset tokens, invitations, operation IDs, payment/confirmation IDs. If the token (not the session) is the only check, victim-A token completes attacker-B flow - that is an account-takeover class result when the token type is reset/verification/invite.

### 6. Stale-state usage

Replay consumables long after their lifecycle ended: completed verification links, cancelled transactions, stale JWTs/session cookies, consumed nonces, previous-step tokens, expired quotes. "Expired" must be enforced server-side at read time, not assumed.

## Alternate-Endpoint Rule

The state machine exists per route family. The web UI route may enforce step 2 while the equivalent mobile endpoint, legacy API, GraphQL mutation, or REST v1 route skips the check. For every bypass that FAILS on the primary route, replay it once through each alternate route family before closing:

```text
web UI endpoint / mobile endpoint / legacy API / GraphQL mutation / REST v1 vs v2
```

## Evidence Contract

Not enough: step 4 endpoint returned 200.
Good proof: the unverified account reached a verified-only state/function - e.g. the profile now reports verified, or the verified-only endpoint returned account-private data without the precursor steps; capture the state marker before and after.

Not enough: an expired link returned 302.
Good proof: the expired invitation actually granted tenant membership - membership list or session now shows the access.

Verify PERSISTENT state: re-read the object (profile, order, membership) after the abuse, not just the immediate response.

## Common Misses

- Only testing forward skips (1->4); reverse ordering and replay are separate bug classes
- Forgetting the state marker may be client-held: the server trusts a submitted "stage"/"status" field it never re-derives
- Not capturing the exact legitimate multi-step request sequence first (baseline for all replays)
- Ignoring async steps: "processing" states that can be raced or skipped while incomplete
- Testing only the primary route family and closing on its 403

## False Positives

- Terminal step returning a GENERIC page (re-renders form, empty 200) without state change - the backend checked the precursor; not a bypass
- Response caching making a skipped step look successful - re-fetch with a fresh request before concluding
- Cross-session success that only reflects YOUR other session already having completed the flow legitimately

## Xalgorix Tool Strategy

- browser_action to walk the full legitimate flow and capture every step request (the baseline corpus)
- http_request to replay captured steps out of order, repeatedly, and across sessions
- authz_matrix for cross-account token/context replays
- record_hypothesis per (flow x abuse x route family); add_hypothesis_evidence with before/after state markers
- HAR capture retains the authenticated step sequence for exact replay

## When to Load a Specialist Skill

- Auth/verification/reset flows -> authentication-session-testing (token binding depth)
- Payment/checkout deep technique -> testing-ecommerce-and-payment-logic
- Concurrency on the same step -> race-condition-testing
- API workflow abuse patterns -> api-business-flow-abuse (api-security)

## Stopping Rule

Stop when: the flow machine is mapped (states + markers), each of the six abuses has been tried against each major flow at least once, alternate route families have been spot-checked for flows that looked enforced, and no new state marker appears from two further flow walks. Then pursue the deepest proven bypass to persistent impact instead of enumerating every remaining flow permutation.

## Handoffs

- application-attack-surface-modeling - workflow/invariant inventory
- business-logic-testing - when the abuse is about VALUES not order
- authorization-testing - when the skipped step was an authorization gate
