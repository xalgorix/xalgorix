---
name: rpc-api-security
description: JSON-RPC and XML-RPC API security testing — method enumeration, unauthenticated and privileged RPC calls, batch authorization inconsistencies, method confusion, ID handling, and hidden internal method discovery
intent: offensive
protocol: json-rpc
---

# RPC API Security (JSON-RPC / XML-RPC)

## Purpose
Exploit RPC-style APIs: enumerate callable methods, invoke privileged or internal methods with lower-privilege sessions, abuse batch semantics, and exploit ID/param handling — applying the same differential evidence contracts as REST skills.

## Preconditions
- An identified JSON-RPC (POST with `{"jsonrpc":"2.0","method":...}`) or XML-RPC (`<methodCall>`) endpoint
- At least one valid session for differential testing
- The target's error behavior catalogued (invalid method, invalid params, authz failure)

## Attack Surface Signals
- JSON bodies with `jsonrpc`, `method`, `params`, `id` keys
- `Accept: application/json` endpoints rejecting normal REST calls
- Known frameworks: Ethereum nodes (`eth_*`), Solr, supervisor, MantisBT, WordPress XML-RPC, CMS RPC layers
- `/rpc`, `/jsonrpc`, `/xmlrpc.php`, `/api/jsonrpc` paths

## Methodology

### Step 1: Error-Triplet Baseline
```bash
curl -sk -X POST "https://TARGET/rpc" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"no_such_method","params":[],"id":1}'
curl -sk -X POST "https://TARGET/rpc" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"target_method","params":[],"id":1}'
```
Compare: unknown-method error vs real-method response (authz error, param error, or execution). Different error strings = method EXISTS and is callable to some depth. Catalog these before concluding anything.

### Step 2: Method Enumeration
```bash
for m in user.list user.get admin.list system.listMethods rpc.discover \
  getRoles updateUser deleteUser debug.status internal.exec importData; do
  resp=$(curl -sk -X POST "https://TARGET/rpc" -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$m\",\"params\":{},\"id\":1}")
  echo "$m => $resp" | head -c 200; echo
done
# Framework-specific discovery
# system.listMethods (XML-RPC), rpc.discover (JSON-RPC OpenRPC), eth_* on chain nodes
```
Treat readable responses as CANDIDATES — a finding requires a concrete unauthorized outcome.

### Step 3: Privileged Method Invocation
```text
1. Invoke the privileged method legitimately as the admin/high session → record the effect (baseline)
2. Same exact call with the lower-privilege session → if it executes identically: BFLA finding
3. Same call anonymous → additional finding surface
Verify the privileged effect with a second read (role changed, user created, data returned).
```

### Step 4: Param and Type Abuse
- Positional vs named params: `params:[victim_id]` vs `params:{"id":victim_id}` — some stacks authorize one shape
- Extra params: `params:[own_id, {"role":"admin"}]`
- Type confusion: string IDs vs numeric; null params; nested objects where scalars expected
- Parameter injection: `params:{"id": {"$ne": null}}` (NoSQL operator reaching the RPC layer)

### Step 5: Batch Authorization Inconsistencies
```bash
curl -sk -X POST "https://TARGET/rpc" -H "Content-Type: application/json" -d '[
  {"jsonrpc":"2.0","method":"user.get","params":[123],"id":1},
  {"jsonrpc":"2.0","method":"user.get","params":[456],"id":2},
  {"jsonrpc":"2.0","method":"admin.purgeUsers","params":[],"id":3}
]'
```
Some implementations authorize the batch container, not each method — mixed-role batches can smuggle privileged calls. Per-item responses must be checked individually: one executed admin.purgeUsers result = finding.

### Step 6: ID and Notification Handling
- `id` reflection: does the response echo attacker-controlled `id` values into logs/views (injection into ID fields)?
- Notifications (`id` omitted): fire-and-forget calls that may skip authz/logging
- `id` collisions in batches: response misattribution between calls
- Error responses leaking stack traces, file paths, versions (misconfig chain)

### Step 7: XML-RPC-Specific
```xml
<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>
<!-- WordPress/MantisBT: system.multicall as auth-bypass batch primitive
     (password brute force via multicall, historically); pingback.ping as
     SSRF primitive (chains into api-ssrf) -->
```

## Evidence Contract
An RPC finding requires:
1. Baseline: the method's legitimate behavior (privileged execution observed or documented)
2. Manipulation: the lower-privilege/anonymous/param-abused invocation
3. Differential: the privileged effect actually happened for the unauthorized caller (verified by a second read), or privileged data returned in the result

**NOT evidence**: a different error string, method existence, a 200 with `{"result":null}`, batch accepted but no per-item effects

## Common Misses
- Error-string differences never catalogued, so method existence is missed
- Batch per-item results never inspected individually
- Named/positional param shapes not both tried
- Notifications (no `id`) never tested for authz bypass
- Framework-specific hidden methods (system.*, internal.*, debug.*) not probed
- XML-RPC system.multicall/pingback primitives forgotten

## False Positives / Non-Findings
- Unknown-method errors (routing working)
- `result: null` on authorized methods without state change
- Batch rejected wholesale (per-method authz working)
- Enumerated methods that exist but correctly enforce authorization

## Xalgorix Tool Strategy
- `http_request`/curl for precise RPC envelopes; Python for batch construction and per-item parsing
- `oob_callback` where RPC methods accept URLs (pingback SSRF chains)
- `authz_matrix` for multi-role method differentials

## Stopping Rule
Every enumerated method x every session tier x positional/named/extra/type-abused params x batch and notification variants.

## Handoff
Report the method, session tier, param manipulation, and the verified unauthorized effect. URL-accepting methods chain into api-ssrf; chain-node RPC (eth_*) into blockchain-specific skills.