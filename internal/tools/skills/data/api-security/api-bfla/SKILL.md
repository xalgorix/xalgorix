---
name: api-bfla
description: Broken Function Level Authorization (BFLA) testing — invoking administrative API functions with lower-privilege sessions via method, version, path-normalization, and override-header variants (OWASP API5)
intent: offensive
protocol: rest
---

# API BFLA — Broken Function Level Authorization (OWASP API5)

## Purpose
Test whether regular (or partially privileged) users can invoke administrative API functions that should be restricted to higher roles.

## Preconditions
- At least one low-privilege session (plus admin session when available, to build the expected-behavior baseline)
- Admin endpoint/verb inventory from OpenAPI specs, JS bundles, error messages, or documentation
- No assumption that the UI hides a function — the backend must be tested directly

## Attack Surface Signals
- Paths containing admin/manage/internal/system/console/backoffice/ops
- Documentation or JS referencing privileged operations not linked in the UI
- Role-conditional features in frontend code (the API behind them)
- Management verbs on normal resources: `PUT /users/{id}/role`, `POST /users/{id}/disable`, `DELETE /audit/logs`

## Methodology

### Step 1: Build the Admin Inventory
```bash
for path in admin manage management internal system console backoffice ops \
  admin/users admin/settings admin/config admin/logs admin/reports admin/billing; do
  for method in GET POST PUT PATCH DELETE; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" -X $method \
      -H "Authorization: Bearer LOW_PRIV_TOKEN" "https://TARGET/api/v1/$path")
    echo "$method /$path -> $code"
  done
done
```
Treat any non-401/403 outcome as a CANDIDATE — never as a finding by itself.

### Step 2: Role-Differential Matrix
```text
admin legitimate request on function F   → 200 + privileged effect (baseline)
same request with lower-privilege session  → candidate if NOT 401/403
same request anonymous                    → candidate if NOT 401/403
verify effect with an authorized read     → finding only if the privileged
                                            state actually changed / data returned
```
Use `authz_matrix` when multiple roles exist; test moderator/support tiers too, not just user-vs-admin — partial-role gaps are common.

### Step 3: Method and Override Variants
```bash
# Verbs the gateway forgot
for method in PUT PATCH DELETE; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X $method \
    -H "Authorization: Bearer LOW_PRIV_TOKEN" "https://TARGET/api/v1/admin/settings")
  echo "$method -> $code"
done
# Override headers when the real method is filtered
curl -sk -X POST -H "X-HTTP-Method-Override: DELETE" \
  -H "Authorization: Bearer LOW_PRIV_TOKEN" "https://TARGET/api/v1/audit/logs"
```

### Step 4: Path-Normalization Bypass
Case (`/Admin/`), URL-encoding (`%61dmin`), trailing slash, `;` matrix params, `..` traversal, and `.json`/`/` suffixes can dodge gateway ACL rules while the backend still routes. Test each against a known-admin path with the low-privilege session.

### Step 5: Version Drift
`/api/v2/admin/...`, `v0`, `beta`, `internal`, `legacy` frequently lack the middleware v1 enforces. Re-run the full admin inventory under each discovered version prefix.

### Step 6: Privilege Escalation via Self-Update (mass-assignment path)
`PUT /api/v1/users/me` with `role`, `is_admin`, `group_id`, `tenant_id` — if accepted, read back `users/me` and verify the role actually persisted (evidence contract shared with api-bopla).

## Evidence Contract
A BFLA finding requires one of:
- Privileged DATA returned to the lower role (e.g., full user list with emails)
- Privileged OPERATION executed and verified via a second authorized read (role changed, user disabled, audit log actually deleted)
- A function unavailable to the baseline role succeeds for a lower role

**NOT evidence**: 404 (route doesn't exist), 405 (method blocked), 422 (validation rejected before authz), 500 (crash ≠ authorization), empty bodies, generic framework pages, OPTIONS output, redirect-to-login. These are at most CANDIDATES requiring a confirmed privileged outcome.

## Common Misses
- Only GET tested; PUT/DELETE on admin paths skipped
- `X-HTTP-Method-Override` / `X-Method-Override` headers never tried
- Path-normalization variants never tried
- Moderator/support roles never tested (partial gaps)
- Shadow API versions (`/api/v2/admin`) never swept
- Silent successes: non-200 body but the operation executed — always re-read state

## False Positives / Non-Findings
- A function genuinely available to the caller's role
- 404/405/422/500 on an admin path (blocked, nonexistent, or validation-failed)
- Cached/static responses; OPTIONS preflight output
- Admin UI accidentally public but API enforces authorization (test the API, report what the API does)

## Xalgorix Tool Strategy
- `authz_matrix` for multi-role differentials
- `http_request`/curl for verb sweeps and override headers; ffuf for path-variant sweeps
- `terminal_execute` + Python for the full method x version x path-normalization matrix

## Stopping Rule
Every privileged function x every role below its requirement x every method/override/version/normalization variant, with verified privileged outcomes.

## Handoff
Report function, the role that should be required, the role that succeeded, the exact variant used, and the verified privileged data or state change.