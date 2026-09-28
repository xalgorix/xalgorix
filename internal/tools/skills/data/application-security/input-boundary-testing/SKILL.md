---
name: input-boundary-testing
description: Reason about every parameter expected domain and violate it - boundary values, type and shape
  confusion, encoding differentials, duplicate parameters, query/body and header conflicts, nested-structure
  abuse - generating hypotheses that scanners miss and routing class signals to specialist skills.
domain: cybersecurity
subdomain: application-security
tags:
- input-validation
- type-confusion
- boundary-testing
- mass-assignment
- parser-confusion
- parameter-tampering
version: '2.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
intent: offensive
phase: application-testing
blackbox: true
---

# Input Boundary and Type-Confusion Testing

## Purpose

Scanners send known payload strings; this skill instead reasons about what each parameter MEANT to be and what happens when it arrives as something else. Type, shape, encoding, and multiplicity violations find the bugs pattern-matching cannot: parser confusion, mass assignment, silent coercion, and validation layers that disagree with processing layers. This skill generates HYPOTHESES; when a class signal appears, the specialist skill handles exploitation depth.

## Entry Conditions

- Meaningful parameters identified in state-changing or privileged requests (ids, quantities, prices, roles, emails, flags, tenant ids, file paths, search/sort/filter params)
- A captured legitimate baseline request per target endpoint

## Step 1: Expected-Domain Reasoning

For each parameter write down its expected domain. `quantity expects positive integer`, `role expects enum`, `user_id expects string uuid`, `sort expects column name`. The expected domain is the INVARIANT; every test violates one aspect of it. Do not waste rounds on display-only parameters - prioritize parameters that reach authorization decisions, money, state transitions, or queries.

## Value Boundaries (for numeric-ish parameters)

```text
0, -1, MAX_INT (2147483647), MAX_INT+1 (2147483648), -MAX_INT-1
float where int expected (1.5, 0.001, 1e3, 1e309)
string where number expected ("10", " 10", "10\n", "0x10", "1,000", "10.0")
null, empty string, absent field
true / false (JSON booleans where int/string expected)
```

Integer overflow/underflow at parse, store, and compute time are three different bugs - if 2147483648 is accepted, observe what got stored (2000000000? wrapped negative? rejected at a later layer?).

## Type and Shape Confusion

- Array where scalar expected: `{"quantity": [1,2,3]}` and `quantity[]=1&quantity[]=2`
- Scalar where array expected; object where scalar expected (`{"user_id": {"$gt": ""}}` style NoSQL probes when the backend smells document-y)
- Nested structures: `{"user": {"role": "admin"}}` where the endpoint expects `{"name": "x"}` - does a deep-merge persist the extra object?
- Unexpected object fields: add `role`, `tenant_id`, `is_admin`, `permissions`, `price`, `status` to update endpoints - MASS-ASSIGNMENT hypothesis; persist-then-re-fetch is the proof
- Duplicate JSON keys: `{"role":"user","role":"admin"}` - front parser and back parser may pick different winners

## Encoding and Parser Differentials

- Content-Type cross-delivery: the same operation as `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain` (and XML where accepted) - validators and deserializers frequently cover only the one the UI sends
- Content-Type confusion between validation and processing layers: JSON body declared with a form Content-Type (or vice versa) to route through the unguarded deserializer
- Duplicate parameters in forms: `role=user&role=admin` - which value wins at validation time vs storage time?
- Query/body conflicts: `?id=1` with body `{"id":2}` - authorization reading one, processing the other
- Header/body conflicts: tenant id in header vs body
- Case variations: `UserID`, `user_id`, `userId`; key folding in frameworks (`X-Tenant-ID` vs `x-tenant-id`)
- Unicode: lookalike ids, `％2e` full-width percent, unicode normalization on usernames/emails/paths
- Null bytes in strings and filenames; double URL-encoding (`%252f`); overlong UTF-8 where the platform tolerates it

## Methodology

```text
list meaningful parameters per endpoint (from the application model)
-> write the expected domain for each
-> ONE violation per request (attribute results cleanly)
-> observe: response AND stored state AND downstream effect (re-fetch)
-> classify the anomaly:
     silent acceptance -> coercion bug / missing validation
     error leak -> information disclosure lead
     class signal (SQL/NoSQL error, template output, redirect, fetch) -> specialist skill
-> record hypothesis/evidence in the ledger with the exact request
```

## Evidence Contract

Not enough: the endpoint accepted quantity -1 (HTTP 200).
Good proof: the stored/persisted object reflects the out-of-domain value (negative quantity persisted as a credit, wrapped total persisted, role field readable in the re-fetched object).

Not enough: duplicate keys returned 200.
Good proof: the SECOND value took effect in application behavior (role=admin visible in a re-fetch or in what the session can now access).

Pure type-rejection with clean errors is a NEGATIVE - close it and move on.

## Anomaly-to-Specialist Routing

| Signal observed | Load specialist |
|---|---|
| SQL/NoSQL error, boolean-based difference in query behavior | sql-injection / nosql-injection |
| `{{7*7}}`-style evaluation, template error | ssti |
| Server-side fetch attempt from an injected URL | ssrf |
| Role/admin field persisted | exploiting-mass-assignment-in-rest-apis |
| Path-shaped value reaching a file operation | path-traversal-lfi-rfi |
| Reflection with markup interpretation | xss |
| Deserialization of attacker-shaped structures | insecure-deserialization |
| Parser confusion between framework layers | security-control-differential-testing (this category) |

## Common Misses

- Testing values without a baseline: you cannot tell anomaly from normal without the legitimate request
- Only the UI-used Content-Type is ever tested - the alternate encodings are where validator gaps live
- Ignoring stored-state verification (a 200 means nothing; the re-fetch means everything)
- Skipping duplicate-parameter tests on endpoints that "obviously" take one value
- Not trying arrays/objects on scalar fields in JSON APIs - coercion and loop-over-object bugs live there
- Forgetting the query/body conflict class when the endpoint reads both

## False Positives

- 422/400 rejections with clean errors = validation working; not a finding
- Client-side-only weirdness (UI shows the tampered value but server stored the real one)
- Accepted-but-ignored values (server re-derived the field): missing input trust is only a finding when the CLIENT value took effect
- Timeouts from huge payloads = resource-consumption observation at best; classify honestly (api-resource-consumption for API targets)

## Xalgorix Tool Strategy

- http_request for raw single-variable-violation replays (exact Content-Type and body control)
- browser_action to confirm client-side behavior differences and drive flows needing real browsers
- authz_matrix when a shape/encoding violation crosses identities
- record_hypothesis per (parameter x violation-class); attach request + re-fetched state
- Deterministic verifiers the moment a class signal appears - they own the confirmation step

## Stopping Rule

Stop when: every meaningful parameter on privileged/state-changing endpoints has had its domain violated at least once (value class, shape class, encoding class), one alternate Content-Type has been tried per major endpoint family, and two consecutive rounds produce no new anomaly classes. Then hand the strongest signals to the matching specialist and go deep there instead of mutating every remaining permutation.

## Handoffs

- application-attack-surface-modeling - where the meaningful-parameter inventory comes from
- business-logic-testing - when the violated domain is a business rule (quantity, price, coupon)
- security-control-differential-testing - when two layers parse the same bytes differently
- the specialist table above - for exploitation depth once a class signal is live
