---
name: api-bola
description: Broken Object Level Authorization (BOLA/IDOR) testing for REST and GraphQL APIs — object ID harvesting and swapping across paths, query, body, batch, and nested resources with two-account differential evidence (OWASP API1)
intent: offensive
protocol: rest
---

# API BOLA — Broken Object Level Authorization (OWASP API1)

## Purpose
Test whether authenticated callers can access or modify other users' objects by manipulating object identifiers, when the server fails to enforce per-object authorization.

## Preconditions
- At least two accounts with distinct data (the two-account differential is mandatory for confirmation)
- A mapped API surface (consume reconnaissance API discovery; do not re-enumerate here)
- Object IDs observed in requests (numeric, UUID, slug, encoded)

## Attack Surface Signals
- Path segments with IDs: `/orders/1042`, `/users/{id}/documents/{uuid}`
- Query/body parameters: `?order_id=`, `{"userId": ...}`, filter params
- List endpoints that leak other-context IDs (harvest victims here)
- Batch/bulk endpoints accepting arrays of IDs
- GraphQL node/relay IDs (base64 `Order:5003`) and `user(id:)` arguments

## Methodology

### Step 1: Harvest Object IDs
```bash
# Legitimate IDs first (own account), then victim IDs from list endpoints,
# search responses, exports, logs, comments, and any shared context.
curl -sk -H "Authorization: Bearer USER_A" "https://TARGET/api/users/me" | jq -r '.id'
curl -sk -H "Authorization: Bearer USER_A" "https://TARGET/api/users/me/orders" | jq -r '.orders[].id'
```

### Step 2: Two-Account Differential
```bash
# User B legitimately accesses their own object (baseline B)
curl -sk -H "Authorization: Bearer USER_B" "https://TARGET/api/orders/5003" > tmp/b_own.json
# User A attacks the same object
curl -sk -H "Authorization: Bearer USER_A" "https://TARGET/api/orders/5003" > tmp/a_cross.json
# User A's own object (baseline A) and anonymous request complete the matrix
curl -sk -H "Authorization: Bearer USER_A" "https://TARGET/api/orders/5001" > tmp/a_own.json
curl -sk "https://TARGET/api/orders/5003" > tmp/anon.json
diff <(jq -S . tmp/b_own.json) <(jq -S . tmp/a_cross.json)
```
Confirm the response is User B's ACTUAL data (match a known victim-owned value: email, address, total), never an empty shell or generic 200.

### Step 3: Test Every ID Location
- Path: `/orders/{victim}` and nested `/users/{victim}/orders/{victim_order}`
- Query: `?user_id={victim}`, filter params
- JSON body: `{"order_id": victim}` on POST detail/export endpoints
- Parameter pollution: path carries your ID, query carries victim's (and vice versa)
- Batch arrays: mix own + victim IDs in one bulk request
- GraphQL: `user(id:"VICTIM"){email orders{edges{node{totalAmount}}}}` and relay `node(id:"T3JkZXI6NTAwMw==")`

### Step 4: Test Every Method
```bash
for method in GET PUT PATCH DELETE; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X $method \
    -H "Authorization: Bearer USER_A" "https://TARGET/api/addresses/2002")
  echo "$method: $code"
done
```
GET may 403 while PUT/PATCH/DELETE succeed. For write hits, read back as the victim (or admin) to verify the change persisted.

### Step 5: Version and Shape Drift
- `/api/v2/...` often lacks the authz middleware v1 has; sweep v0/beta/legacy/internal too
- ID encoding variants: increment/decrement sequential IDs, decode base64/hashids, swap UUID casing
- Same object via different routes: direct ID, search, export, mobile-specific endpoints

## Evidence Contract
A BOLA finding requires ALL of:
1. Baseline: victim legitimately accesses their object; attacker legitimately accesses own object
2. Manipulation: attacker's session references the victim's object ID
3. Differential: attacker receives the victim's actual data (verified by a known victim-owned value) or modifies/deletes it (verified by read-back)
4. Anonymous/low-priv controls show the endpoint is otherwise protected

**NOT evidence**: HTTP 200 with an empty body, a 200 on the attacker's own object, 404/405 responses, existence of an ID parameter, error-message leaks

## Common Misses
- Write verbs (PUT/PATCH/DELETE) never tested — read is 403 but write succeeds
- IDs only swapped in the path; query/body/batch/nested locations missed
- UUIDs assumed safe — they leak via list endpoints, exports, shared contexts
- Only one API version tested
- GraphQL global relay IDs not base64-decoded
- Response assumed to be victim data without matching a known value

## False Positives / Non-Findings
- Public-by-design objects (public profiles, shared documents, storefront products)
- 200 returning the attacker's own data regardless of requested ID
- Soft-deleted objects returning 404 for everyone
- Admin/support tooling where cross-object access is intended

## Xalgorix Tool Strategy
- `authz_matrix` for automated A/B session differentials
- `http_request`/curl for precise ID swaps; Python for batch sweeps across harvested IDs
- ffuf with harvested ID wordlists for sequential enumeration

## Stopping Rule
Every object-ID-bearing endpoint x every ID location x every method, with a verified victim-data differential before reporting.

## Handoff
Report endpoint, method, ID location, victim object reference, and the concrete victim-owned value returned or changed. Property-level leaks within a cross-object read also belong to api-bopla; write-side role changes belong to api-bfla.