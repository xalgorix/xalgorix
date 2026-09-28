---
name: application-attack-surface-modeling
description: Build a working model of the application as a system - roles, resources, workflows, state
  transitions, trust and tenant boundaries - from black-box behavior, and turn that model into prioritized
  hypotheses. The foundation skill that converts a recon endpoint list into application-level reasoning.
domain: cybersecurity
subdomain: application-security
tags:
- application-security
- attack-surface
- threat-modeling
- hypothesis-generation
- blackbox
version: '2.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
intent: offensive
phase: application-testing
blackbox: true
---

# Application Attack-Surface Modeling

## Purpose

Reconnaissance produces a list of routes and endpoints. That list is not yet an application. This skill turns observed runtime behavior into a structured model - who exists, what exists, what flows exist, what states exist, and where the boundaries are - and converts the model into testable hypotheses for the ledger. Load this skill when the endpoint inventory feels like "many URLs, little meaning", or before starting systematic application-level testing.

## Entry Conditions

- Reconnaissance has produced a concrete endpoint/page inventory (including client-side routes from discover_client_routes)
- Login flows, forms, and API surfaces are mapped at a surface level
- You need to decide WHICH application-level attacks to run and in what order

## Application Model: What to Capture

Work through these dimensions in order; each one generates hypothesis material:

### 1. Roles and privilege states

Enumerate the distinct identities the application recognizes, not just the accounts you hold:

```text
Anonymous
  -> signup -> User
  -> email verification -> Verified User
  -> subscription -> Pro User
  -> invite member -> Organization Admin
  -> platform grant -> Moderator / Support / Owner
```

Signals for role discovery: signup/register forms, pricing tiers, invite flows, admin links, role names in API responses, menu differences between your test accounts, X-Tenant-ID / X-Org-ID headers, role claims in decoded cookies/tokens.

### 2. Resources and object types

Every ID-bearing endpoint names a resource type: users, orders, documents, invoices, tickets, messages, api_keys, webhooks, exports, workspaces, tenants. For each: how are IDs generated (sequential, UUID, slug)? Who can create/read/update/delete? Are they tenant-scoped or global? Sequential IDs across tenants are an enumeration lead; UUIDs are not.

### 3. Workflows and state transitions

Every multi-step flow is a state machine. For each transition capture:

| Field | Question |
|---|---|
| Expected transition | e.g. OrderCreated -> Paid |
| Who can initiate | role AND ownership AND tenant |
| Required precursor state | what must be true first |
| Invariant | what must remain true (one coupon per order, one vote per user) |
| Externally triggerable | webhooks, emails, background jobs, third-party callbacks |
| Async? | polling endpoints, job status routes, out-of-band notification |

Representative flows to map: signup/verification, password reset, MFA enrollment, checkout/payment/refund, KYC/approval, invite/accept, subscription change/cancel, file import/processing, content publish/moderation, support ticket lifecycle, export/report generation.

### 4. Trust and privilege boundaries

- Boundary between anonymous and authenticated (which routes sit exactly on it?)
- Boundary between roles (user vs moderator vs admin vs owner)
- Boundary between tenants (org/workspace/project IDs; where do they appear - path, query, body, header?)
- Boundary between client and server (values recomputed server-side vs trusted from the client: totals, prices, permissions, role fields)
- Boundary between route families (web UI route, mobile API, legacy API, GraphQL - same state checks?)

### 5. Sensitive operations

List operations where a broken rule causes real impact: money movement (charge, refund, withdraw, transfer, credit), access changes (invite, role change, API key mint, MFA change, email change), data egress (export, report, share link), destructive actions (delete, cancel, purge), and integration surfaces (webhook URLs, third-party fetch, import-by-URL).

## From Model to Hypotheses

For every transition and boundary, generate candidate violations and record them with record_hypothesis (set vuln_class, endpoint, parameter, role, baseline, next_action):

- Who else can initiate? - every other role/tenant replaying the exact request (authorization-testing)
- What if the precursor state is missing? - call the terminal step first (workflow-state-machine-testing)
- What breaks the invariant? - quantity, count, total, token reuse, concurrency (business-logic-testing, race-condition-testing)
- What does the input not expect? - type/shape/encoding beyond the parameter domain (input-boundary-testing)
- What does a boundary layer interpret differently? - CDN/WAF/proxy/gateway vs application (security-control-differential-testing)
- Who receives this data? - over-fetch by role, tenant, serializer (application-data-exposure-testing)

Chaining: preserve weak intermediate observations in the ledger instead of discarding them as low-impact. Username enumeration + reset weakness becomes account takeover; invite leakage + object-level access becomes tenant breach. A primitive that looks minor may be the first link of a chain - record it, do not delete it.

## Xalgorix Tool Strategy

- browser_action / authenticated browser session: walk flows as a real user and observe state changes, menus, and client state machines
- discover_client_routes on the root/login page: extract dynamic routes before modeling
- http_request: replay captured steps outside the browser to test each boundary
- HAR/proxy capture: retain authenticated traffic as the baseline corpus for replays
- record_hypothesis / claim_next_hypothesis / add_hypothesis_evidence: the model violations ARE the hypothesis queue
- authz_matrix: settle "who else can initiate" in one call once a second account exists
- If source is attached: scan_source_routes / code_search to find hidden routes and enrich the model - leads only, never findings without runtime proof (see source-assisted-analysis)

## Common Misses

- Modeling only the happy path shown by the UI - admin, moderation, and background-job transitions never appear in your own navigation
- Missing asynchronous jobs: an export POST that returns 202 means a second state to poll - the poll endpoint is part of the model
- Ignoring the client-side state machine in JS bundles: route guards reveal expected role rules the backend may not enforce
- Treating tenant IDs as opaque: they are boundaries, and every place they appear is a boundary test point
- Modeling objects but not their ownership transitions: share/transfer/revoke create temporary states where checks are frequently forgotten

## False Positives

- A 403 on a route does not mean the boundary is enforced for every method, version, or role - it is a single observation, not a rule
- Menu absence is not access control - the model admin transitions must be tested directly, not inferred from the UI
- Sequential IDs are a hypothesis for enumeration, not a finding until cross-identity access is proven

## Stopping Rule

The model is complete enough when: every discovered workflow has initiator/precursor-state/invariant annotations, every role/tenant boundary has at least one boundary-testing hypothesis, and two further interactions produce no new resource type or transition. Stop modeling then; pursue the highest-value hypotheses deeply instead of endlessly broadening the model.

## Handoffs

- authorization-testing - boundary replay methodology (authz_matrix first)
- workflow-state-machine-testing - state-machine abuse
- business-logic-testing - invariant violation
- race-condition-testing - concurrency abuse
- input-boundary-testing - parameter domain violation
- api-security skills - when the surface is an API (api-bola, api-bfla, api-business-flow-abuse)
- reconnaissance skills - for more surface; this skill assumes a baseline inventory
