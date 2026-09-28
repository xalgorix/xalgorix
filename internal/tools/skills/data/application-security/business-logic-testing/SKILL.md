---
name: business-logic-testing
description: Discover the application intended business rules and violate their assumptions - money and value
  manipulation, limit bypass, identity and relationship abuse, state misuse - proving persisted out-of-policy
  outcomes rather than status-code blips.
domain: cybersecurity
subdomain: application-security
tags:
- business-logic
- price-manipulation
- coupon-abuse
- referral-abuse
- limit-bypass
- workflow-bypass
- negative-testing
- owasp
version: '2.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
intent: offensive
phase: application-testing
blackbox: true
---

# Business Logic Testing

## Purpose

Business logic flaws are rules the application MEANT to enforce but does not: prices, quantities, limits, coupons, quotas, identities, and states. Scanners cannot find them because the bug is not in a payload pattern - it is in the gap between intended rule and enforced rule. This skill teaches how to discover the intended rules black-box, then violate one assumption at a time and verify the backend actually persisted the out-of-policy outcome.

## Entry Conditions

- The application has any business rules: prices, quantities, coupons, credits, quotas, trials, referrals, invites, approvals, refunds, balances, votes, subscriptions
- You can perform at least one legitimate transaction to establish a baseline

## Step 1: Discover the Intended Rules

Black-box rule discovery from: UI copy ("one per customer", "limit 3", "non-refundable"), error messages on first violation (the app tells you the rule it thinks it enforces), pricing pages and ToS, how a legit transaction progresses (which fields are client-supplied vs recomputed), and client-side validation code (what the frontend refuses reveals what the backend SHOULD check).

Record each discovered rule as: rule, where observed, and the request that would violate it.

## Step 2: Establish a Legitimate Baseline

Perform the transaction normally once - capture every request. The baseline tells you which parameters the client controls, what a normal response looks like, and what state changed. Never report a manipulation without having observed the legitimate behavior of the same flow.

## Step 3: Identify Attacker-Controlled Variables

For each request in the flow: which values does the server accept from you? Price, total, quantity, discount, currency, role, plan, ids, coupon, timestamps, state? Any value that should be server-derived but appears client-supplied is a primary target.

## Violation Catalog

### Money and value
- Negative quantity (credit instead of charge); zero price; quantity 0.001
- Client-controlled price/total at checkout; currency mismatch between item and charge
- Discount stacking exceeding 100%; repeated coupon application; rounding inconsistencies (0.005 boundaries)
- Integer overflow: quantity 2147483647, quantity 2147483648, price 99999999999999999999
- Circular value: buy credit with credit (gift card purchased with gift-card balance), refund into a different currency or wallet, apply store credit above cart total and keep the change
- Scientific notation and string numbers where a parser differs from the validator ("1e3", "10.0", " 10", "10\n")

### Limits
- Purchase limits, free-trial limits, account limits, storage/usage quotas, download limits, invite limits, withdrawal limits, OTP/attempt limits - every "once", "max", "only" the UI promises. Off-by-one tests (limit N, try N and N+1); limits enforced client-side only; limits that count before state changes (cancel and repeat).

### Identity and business relationships
- Invite yourself; reuse an invite; accept an expired invite; invite with a role higher than your own
- Transfer ownership to yourself or across tenants; manipulate creator/owner/id fields in requests
- Create a privileged resource through a low-privilege workflow (e.g. admin-configured webhook through the user API)
- Referral credit to your own alternate account; earn-then-cancel (points/credits kept after refund)

### State misuse
- Use an expired item (coupon, trial, session, subscription)
- Reuse a completed one-time action (verification, confirmation, vote, redemption)
- Modify a cancelled/completed order; refund an already-refunded purchase
- Verify an account twice; reuse a payment confirmation; reuse one-time links

## Methodology

```text
understand intended rule (from UI/errors/behavior)
-> establish legitimate baseline (captured)
-> identify attacker-controlled variables
-> violate ONE invariant at a time
-> observe backend state (re-fetch the object - do not trust the response alone)
-> verify persistent business outcome
-> report with rule violated + baseline + tampered request + resulting state
```

Violate one variable at a time: if quantity AND price are both tampered, you cannot attribute the outcome.

## Evidence Contract

Not enough: POST /coupon returned 200 twice.
Good proof: the same single-use coupon produced two persisted discounts/orders - re-fetch the cart/orders and show both entries, or show the coupon redemption counter incremented twice.

Not enough: checkout accepted total 0.01.
Good proof: an order exists in the order history with total 0.01 and a real product attached (server persisted the out-of-policy outcome).

Not enough: negative quantity got a 200.
Good proof: balance/credit reflects the negative-side effect (credit issued, inventory incremented, refund created).

Always verify by re-reading state server-side (order history, balance, quota counter) - never report from the immediate response alone.

## Common Misses

- Tampering only the obvious fields: totals sometimes come from a session-stored cart - poison the cart in an earlier step
- Skipping the re-fetch: the response says 200 but the server recomputed everything (tampered value ignored)
- Not testing the cancel/refund/withdrawal side of a flow - money-out operations are guarded less than money-in
- Forgetting cross-account variants: coupon per USER vs per ACCOUNT vs per EMAIL vs per CARD
- Not re-testing after state changes: a rule enforced on a fresh order may not be enforced on an edit/cancel path

## False Positives

- HTTP 200 with the value silently recomputed server-side - not a flaw, just a client that lies
- Error responses that LOOK like acceptance (soft-degrade patterns)
- Coupon stacking that the business explicitly allows (check UI copy first)
- Repeated 200s where the backend is idempotent (single persisted effect) - that is correct design; move to race-condition-testing if the effect SHOULD multiply

## Xalgorix Tool Strategy

- browser_action to walk the legitimate flow and capture the multi-step requests
- http_request to replay steps with one variable tampered
- authz_matrix when the violation crosses identities (whose coupon, whose quota)
- record_hypothesis per rule violation; attach baseline + tampered requests + re-fetched state via add_hypothesis_evidence
- race-condition-testing when a limit must be bypassed by concurrency rather than value manipulation

## When to Load a Specialist Skill

- E-commerce/payment-specific deep technique -> testing-ecommerce-and-payment-logic
- Concurrency-needed limit bypass -> race-condition-testing
- Skipping workflow steps rather than values -> workflow-state-machine-testing
- API business-flow abuse patterns -> api-business-flow-abuse (api-security)
- Price/role fields persisted via extra parameters -> exploiting-mass-assignment-in-rest-apis

## Stopping Rule

Stop broad mutation when: every discovered business rule has had its primary invariant violated once, all money/limit/identity/state categories are represented in tested rules, and no new rule appears from two consecutive legitimate flow walks. Then go deep on the rules that broke (persist proof, chain with other primitives) instead of mutating every remaining permutation.

## Handoffs

- application-attack-surface-modeling - the workflow/inventory model this testing needs
- workflow-state-machine-testing - structural bypasses of the same flows
- race-condition-testing - when one-at-a-time is not enough
