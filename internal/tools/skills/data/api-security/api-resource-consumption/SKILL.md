---
name: api-resource-consumption
description: Unrestricted resource consumption testing (OWASP API4) — rate limit bypass via header/key drift, races, method and identity rotation, plus expensive-query, oversized payload, batch, export, and streaming abuse with threshold-based evidence
intent: offensive
protocol: rest
---

# API Resource Consumption (OWASP API4)

## Purpose
Test whether the target's consumption controls (rate limits, size caps, complexity limits, quotas) can be exceeded so that requests keep being processed beyond the established control — enabling brute force, enumeration, and computational-cost abuse.

## Preconditions
- Measured baselines: what limits exist and where they trigger
- For concurrency races: parallel request capability (Python asyncio or xargs -P)
- High-volume authorization: the runtime policy governs volume; here we test whether the CONTROL works

## Attack Surface Signals
- Rate-limiting headers (429 responses, Retry-After, X-RateLimit-*)
- Endpoints without any visible throttling on expensive operations
- Pagination, search/filter, sort, export/report, batch/bulk, file upload/processing
- Async jobs, streams, subscriptions, WebSocket channels
- Auth endpoints (OTP send, password reset) and availability-check endpoints

## Methodology

### Step 1: Measure the Baseline
```bash
# Find the exact threshold: count requests until 429 (or until behavior changes)
for i in $(seq 1 30); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer TOKEN" \
    "https://TARGET/api/search?q=x")
  echo "$i: $code"
done
```
Record: threshold N, window, which limit (per-IP, per-account, per-token, per-endpoint), and the absence/presence of headers. Absence of headers proves nothing by itself — measure actual behavior.

### Step 2: Rate-Limit Bypass Vectors
```bash
# IP-spoof header spray — gateways often trust the first/last value blindly
for h in X-Forwarded-For X-Real-IP True-Client-IP CF-Connecting-IP Forwarded; do
  curl -sk -o /dev/null -w "%{http_code}\n" -H "$h: 1.2.3.4" "https://TARGET/api/login"
done
# Counter-key drift: same resource, new counter
#   trailing slash, case change, %-encoding, cache-buster query param, alternate version
curl -sk "https://TARGET/api/v1/users"      # hit limit
curl -sk "https://TARGET/api/v1/users/"     # counter reset?
curl -sk "https://TARGET/api/v1/Users?cb=1" # counter reset?
# Method/content-type switch: limit on POST+json may not cover PUT or form bodies
# Identity rotation: username casing, +tags, whitespace variants against per-account limits
```

### Step 3: Concurrency Race
```bash
# Fire N concurrent requests so the check-then-increment window lets a burst through
seq 1 50 | xargs -P 50 -I{} curl -sk -o /dev/null -w "%{http_code}\n" \
  -X POST -H "Authorization: Bearer TOKEN" "https://TARGET/api/coupons/redeem" \
  -H "Content-Type: application/json" -d '{"code":"X"}' | sort | uniq -c
```

### Step 4: Expensive-Operation Abuse (beyond rate limiting)
- Pagination abuse: `?page[size]=100000`, deep-page walks, `offset` without limit
- Search/filter bombs: leading-wildcard LIKE, unbounded `?q=a*`, regex-heavy input against engines that back-track (test catastrophic patterns only with measured cause/effect)
- Oversized bodies: large JSON payloads, deep nesting, huge arrays on parsers without depth limits
- Batch/bulk endpoints: max batch size enforced or not; per-item limits vs per-batch
- Export/report generation: repeated heavy job creation; async job flooding without quota
- File processing: oversized uploads, decompression bombs (zip/pdf), image/PDF conversion queues
- GraphQL complexity: deep queries, aliases, batching (see graphql-api-security)
- Streaming/WebSocket: unbounded subscription fan-out, frame flooding (see websocket-api-security)

### Step 5: Prove the Differential
```text
baseline: N requests → control triggers (429/throttle/delay)
bypass condition (header/path/method/identity/race) applied
→ same endpoint keeps processing (200s or real work visible) well beyond N
→ control circumvented for a meaningful operation (login attempt, OTP send, expensive query)
```

## Evidence Contract
A resource-consumption finding requires:
1. Measured baseline threshold (how the control normally triggers)
2. The controlled bypass condition that defeats it
3. Requests continuing to be processed beyond the threshold (reproducible)
4. Impact tied to a meaningful operation (brute force enabled, cost incurred, queue exhaustion) — not just "no 429 seen"

**NOT evidence**: missing rate-limit headers, a single 429, one timing outlier, "endpoint exists with no visible limit" without a measured baseline

## Common Misses
- Only per-IP limits tested; per-account/token/endpooint limits differ
- Anonymous and authenticated limits not measured separately
- Race windows never tested (sequential requests never exceed the counter)
- Gateway limits tested but direct backend paths (alternate ports/hosts) unthrottled
- Async job endpoints skipped because they "return 202 instantly"

## False Positives / Non-Findings
- 429 with a valid Retry-After being honored (control working)
- Delays from cold caches, not throttling
- Limits enforced at a different layer than observed (e.g., per-token not per-IP)
- Public CDN/cached responses appearing "unlimited"

## Xalgorix Tool Strategy
- `terminal_execute` with curl loops/xargs -P and Python asyncio for concurrency
- `http_request` for precise single probes
- ffuf for high-volume enumeration when a bypass is confirmed

## Stopping Rule
Every limited endpoint x every bypass vector (headers, key drift, methods, identities, races), plus every expensive operation measured for cost-abuse potential.

## Handoff
Report the baseline threshold, the bypass condition, the sustained-processing proof, and the abusable operation. Business-flow limits (coupons, OTPs, inventory) chain into api-business-flow-abuse; per-operation races into the race-condition methodology.