---
name: race-condition-testing
description: Application-level concurrency abuse - identify race-prone business operations (coupons, payments,
  withdrawals, quotas, OTP, invites) and synchronize parallel requests with bounded concurrency to prove a
  duplicated persistent effect: double-spend, limit overrun, duplicate creation, TOCTOU.
domain: cybersecurity
subdomain: application-security
tags:
- race-condition
- concurrency
- toctou
- double-spend
- limit-overrun
- single-packet-attack
version: '2.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
intent: offensive
phase: application-testing
blackbox: true
---

# Race Condition and Concurrency Testing

## Purpose

Many business invariants ("once per user", "balance cannot go negative", "limited stock") are enforced with check-then-act logic that two near-simultaneous requests defeat. This skill covers WHICH operations are race-prone, HOW to synchronize concurrent requests from inside Xalgorix with bounded concurrency, and WHAT proof looks like (a duplicated persistent effect, never N status codes).

## Entry Conditions

- A state-changing operation whose business rule implies exactly-once or limit enforcement
- The operation can be triggered repeatedly in quick succession within scan policy

## Race-Prone Operation Candidates

- Coupon / discount / gift-card redemption (limit: one per user)
- Payment, refund, withdrawal, transfer, balance operations
- Inventory reservation / limited-stock purchase
- Username/account claim, signup with uniqueness, email claim
- Invite acceptance (single slot), role change (grant/revoke races)
- Quota enforcement: storage, usage, API rate budgets, download limits
- OTP usage / verification marking, password reset consumption
- File processing on the same object, double-processing of an async job
- Vote / review / like counters; reward claiming; trial start

Signals in code-less form: any "check then act" wording in error messages ("You have already used this coupon"), counter fields returned by the API, or limits that appear to update AFTER a response.

## Methodology

```text
baseline single request
-> identify the invariant (what must be true about final state)
-> synchronize N concurrent identical requests
-> observe FINAL backend state (re-fetch, never trust the responses alone)
-> repeat enough batches to distinguish race from noise
-> prove persistent impact
```

1. **Baseline**: perform the operation once legitimately; capture the request and the resulting state (balance, counter, list length).
2. **Invariant**: state what must hold ("coupon redemption count per user <= 1").
3. **Synchronize**: fire N identical copies as simultaneously as the platform allows (see techniques). N modest first (5-20), increase only if promising.
4. **Observe final state**: re-fetch the counter/balance/list. Compute how many effects persisted.
5. **Repeat**: races are probabilistic - a single clean batch is NOT a negative; repeat batches (and increase tightness) before concluding not vulnerable. Conversely a single hit IS a positive - reproduce at least once more for confidence.
6. **Prove impact**: show the duplicated effect persists (double credit, two orders, negative balance, redemption count 2).

## Synchronization Techniques (Xalgorix-Native First)

- **Bounded parallel replay via terminal_execute**: a short Python asyncio/httpx or threads+requests script sends N pre-built requests through one event loop, gated on a barrier so they leave within milliseconds of each other. Keep concurrency bounded by the scan rate policy - the goal is tight ARRIVAL, not flooding.
- **Barrier batch with xargs/curl** where scripting is unavailable: pre-stage connections (warming) so only the final request bytes race.
- **HTTP/2 single-packet style**: with h2, multiple streams can carry their final bytes in one TCP packet (last-byte/HEADERS delay). If the target speaks h2, prefer it for tightest arrival.
- **Connection warming**: open and idle connections first, then release all queued requests - cuts jitter dramatically.
- **Multi-endpoint races**: some invariants span endpoints - e.g. change-email and password-reset in parallel, or withdraw + transfer. Synchronize DIFFERENT requests, not just identical ones.
- Optional external tooling (Burp Turbo Intruder single-packet attack) when available and authorized; the methodology above does not require it.

Technique ladder: naive parallel -> warmed connections -> single-packet/last-byte. Escalate only when the previous tier shows near-misses (e.g. responses arrive same millisecond but state stayed consistent).

## Race Classes

- **TOCTOU / check-then-act**: balance/quota checked before write; two writers pass the check
- **Double-spend**: two transfers both accepted against one balance
- **Duplicate creation**: two identical objects (accounts, orders, invites) from one entitlement
- **Limit overrun**: counter limit enforced per-request, not atomically (coupon redeemed N times)
- **Stale-state update**: read-modify-write without locking (points, votes, profile fields)
- **Parallel state transitions**: two different workflow steps accepted on the same object simultaneously

## Evidence Contract

Not enough: two concurrent requests both returned 200.
Good proof: the balance/resource/limit reflects a duplicated effect that should only occur once - balance went negative or two transfers persisted from one balance; coupon redemption counter reads 2; two orders exist for one purchase entitlement.

Attach: baseline request, the synchronized batch description (N, technique), and the BEFORE vs AFTER backend state read. Report the duplicated-effect count.

## Common Misses

- Firing requests "in parallel" that actually serialize (per-connection head-of-line, sequential script) - verify arrival tightness from timestamps
- Never re-fetching final state - reporting from the immediate responses only
- Giving up after ONE clean batch - retry with tighter sync before declaring safe
- Ignoring idempotency: some backends dedupe by idempotency key or request hash - vary nothing but observe; if deduped, test a DIFFERENT action against the same invariant
- Only racing identical requests - multi-endpoint races break invariants that single-endpoint races cannot

## False Positives

- N x 200 with a single persisted effect = correct idempotent design, not a race
- Transient inconsistency that self-heals on next read (eventual consistency) - re-check after a delay; only a durable duplicated effect is a finding
- Rate limiting answered with 429s - that is the control working; racing AROUND it (token bucket refill window) is a separate, weaker observation
- Load-test-scale stress mistaken for a race: the proof is the invariant violation, not request volume

## Xalgorix Tool Strategy

- http_request for baseline and state re-fetches
- terminal_execute for the bounded synchronized batch (asyncio/httpx or threads; respect runtime rate policy - bounded concurrency, never a flood)
- record_hypothesis with the invariant stated up front; add_hypothesis_evidence with before/after state
- browser_action when a race must go through a real client flow (CSRF tokens, dynamic nonces) - capture one legitimate request and clone it for the batch

## When to Load a Specialist Skill

- HTTP/2 protocol-level subtleties, request smuggling interactions -> http-request-smuggling (web-application-security)
- API-specific concurrency patterns (batching endpoints) -> api-resource-consumption (api-security)

## Stopping Rule

Stop racing an operation after: the invariant is stated, two sync-tightness tiers were tried (naive parallel + warmed/single-packet), at least 2-3 batches per tier were run, and final state was re-fetched each time. A proven race: reproduce once more, then move to proving full impact (how far does the double-spend scale?). A clean operation after the ladder: close the hypothesis with the batch evidence attached.

## Handoffs

- business-logic-testing - the invariants worth racing come from here
- workflow-state-machine-testing - racing workflow transitions rather than single operations
- authorization-testing - racing role/grant changes
