---
name: authorization-testing
description: Application-level authorization methodology - horizontal, vertical, and tenant boundary testing,
  ownership transitions, method and route differentials. Replay legitimate privileged requests with lower
  privilege using authz_matrix first to produce differential evidence.
domain: cybersecurity
subdomain: application-security
tags:
- authorization
- access-control
- privilege-escalation
- tenant-isolation
- idor
- bola
version: '2.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
intent: offensive
phase: application-testing
blackbox: true
---

# Authorization Testing

## Purpose

Test whether the application enforces WHO may do WHAT to WHICH object - at every boundary: same-level users (horizontal), privilege levels (vertical), tenants (organizational), and lifecycle states (ownership transitions). This is the methodology layer: it decides which pairs to replay and what counts as proof.

## Entry Conditions

- Any object-id parameter (/api/orders/1042), tenant header, or role-differentiated route is observed
- You hold accounts at two or more privilege levels, or two accounts in different tenants

## Core Strategy: Replay the Legitimate Request, Change Only the Identity

1. Perform the operation legitimately as the owner/rightful role (capture the exact request) - this is the **baseline**
2. Replay the identical request with a lower-privilege or different-identity context
3. Compare: status AND body AND effect on the object
4. **authz_matrix FIRST**: authz_matrix url=<resource> replays your request as the second configured account and as anonymous, then records the cross-identity access differential as exploit-proven ledger evidence. Do not hand-roll multi-account curl comparisons when authz_matrix settles it in one call.

## Boundary Classes

### Horizontal (user -> other user objects)
- A requests B objects across every resource type: profile, orders, messages, documents, settings, payment methods
- Both directions (A->B and B->A); write operations (PUT/DELETE), not just reads
- Confirm the returned data genuinely belongs to the other principal (match IDs/names/emails) - not a benign echo

### Vertical (lower role -> privileged functions)
- Replay exact legitimate privileged requests with the lower-privilege token: admin dashboards, user creation, settings, logs, export, backup
- The frontend hiding an admin menu is not access control - the backend route must be tested directly
- Method swap on protected routes (GET/POST/PUT/PATCH/DELETE) and override headers (X-HTTP-Method-Override, X-Original-Method) - gateways often authorize only the verb the UI uses

```bash
# Method differential on one protected endpoint, as the LOW-privilege user
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" \
    -H "Authorization: $USER_TOKEN" "https://target.example.com/admin/users/5")
  echo "$method -> $code"
done
```

### Tenant isolation
- Tenant IDs appear in: path, query, JSON body, headers (X-Tenant-ID, X-Org-ID), nested resources (/orgs/{id}/projects/{id}/files/{id})
- Swap every occurrence; check each location separately - a request that ignores the body tenant_id but honors the path id has a half-enforced boundary
- Test cross-tenant via every route family: web UI, mobile API, legacy API, GraphQL, export/report endpoints
- Enumeration lead: sequential org/project IDs are guessable across tenants (candidate, not proof)

```bash
# Tenant-B data requested with Tenant-A session
curl -s -H "Authorization: $TENANT_A_TOKEN" \
  "https://target.example.com/api/organizations/tenant-b-id/users" | jq .
# Tenant supplied via header instead of path
curl -s -H "Authorization: $TENANT_A_TOKEN" -H "X-Tenant-ID: tenant-b-id" \
  "https://target.example.com/api/users" | jq .
```

### Ownership transitions (the forgotten states)
- Newly shared object: does the share revoke when the collaborator is removed?
- Transferred object: does the previous owner retain access?
- Revoked access: immediate or eventual enforcement?
- Removed team member: token/session still valid inside the tenant?
- Deleted user: their API keys, sessions, webhooks still active?

### Method and route differentials
- Same operation through /api/v1 vs /api/v2 vs /internal vs GraphQL mutation vs mobile endpoint - each must enforce the same checks
- Unauthenticated replay in addition to low-privilege replay: strip ALL auth headers

## Evidence Contract

```text
legitimate owner/role request (captured baseline)
-> identical request replayed by attacker identity
-> response differential (status/body identical to baseline = boundary broken)
-> the attacker actually received/changed the protected object (match identifiers)
-> report with both request pairs
```

Not enough: User A got HTTP 200. Good proof: User A received User B real protected object (same order ID, total, email), or the delete actually removed B document.

A 403 on one verb is NOT a clean negative until the other verbs, versions, and route families are covered.

## Common Misses

- Testing only reads; writes and deletes are where ownership checks are skipped
- Testing only the route family you crawled (web UI) - the mobile/legacy/GraphQL equivalent is often unprotected
- Forgetting ownership-transition states (share/revoke/transfer) - transient states leak access
- Nested-resource paths where the leaf check exists but an ancestor id is not validated (or vice versa)
- Referer-based or UI-flow authorization that the raw route ignores

## False Positives

- 200 with an empty list or an error body shaped like success - always verify the payload content matches the protected object
- 403 on GET but the finding requires testing writes before declaring the boundary enforced
- Cross-tenant 200 that returns YOUR tenant data re-serialized (id ignored, session tenant used) - that is correct enforcement, not a bypass
- Mass-assignment role changes belong to the mass-assignment specialist: prove the role field was persisted before reporting privilege escalation here

## Xalgorix Tool Strategy

- authz_matrix url=<endpoint> - first call whenever an object-id or authenticated route appears; it records the differential as ledger evidence (report CWE-639 with the differential as proof)
- http_request - exact-request replay across identities
- browser_action - capture legitimate privileged flows (baseline corpus)
- record_hypothesis per boundary pair; claim and close systematically so coverage is visible in the ledger
- ffuf (bounded, -noninteractive, -maxtime) for hidden admin/functional routes the UI never links

## When to Load a Specialist Skill

- REST API object-level patterns -> api-bola (api-security); function-level -> api-bfla
- IDOR enumeration technique -> exploiting-idor-vulnerabilities
- Role via request parameters -> exploiting-mass-assignment-in-rest-apis
- GraphQL-specific authorization -> graphql-api-security
- Session/role-change behavior -> authentication-session-testing

## Stopping Rule

Stop when: every discovered resource type has been exercised horizontally (read AND write), every privileged route family has a vertical replay across available roles, every tenant-id location has been swapped once, and each ownership transition has been driven once. When a boundary proves broken in one route family, still spot-check one alternative family (v1/v2, GraphQL) before closing - but do not exhaustively re-test every family for every object.

## Handoffs

- application-attack-surface-modeling - where the boundaries came from
- business-logic-testing - authorization rules that are business rules (spend limits, approval chains)
- application-data-exposure-testing - over-fetch evidence
