---
name: api-fuzzing-restler
description: Stateful REST API fuzzing with RESTler — compiling an OpenAPI spec into a fuzzing grammar, running test/fuzz-lean/fuzz modes with custom dictionaries, destructive sequences, bug-bucket triage, and coverage verification
intent: offensive
protocol: rest
---

# API Fuzzing with RESTler

## Purpose
Run Microsoft RESTler for stateful, grammar-driven REST API fuzzing: producer-consumer request sequences that surface 500-class crashes, authentication bypasses, resource leaks, injection, and state-dependent bugs that single-request testing misses. Destructive sequences are part of the methodology and are governed by the runtime policy, not by this skill.

## Preconditions
- OpenAPI/Swagger spec (v2 or v3) for the target API
- RESTler installed (github.com/microsoft/restler-fuzzer) with Python 3.12+ and .NET 8
- Working auth (refresh command if tokens expire mid-run)
- Authorization: RESTler creates, modifies, and deletes resources aggressively

## Attack Surface Signals
- Any documented OpenAPI spec (from recon, swagger.json, v2/v3 api-docs)
- APIs with object dependencies: create → update → delete chains
- Endpoints where invalid input handling matters (500s, injection, auth bypasses)

## Methodology

### Step 1: Compile the Grammar
```bash
restler compile --api_spec tmp/openapi.json
```
Inspect `Compile/grammar.py` for unresolved producer-consumer dependencies — endpoints that never get inputs are silently untested.

### Step 2: Configure Auth
Save the following JSON as `restler_user_settings.json`. Supply a reviewed
`refresh_token.py` implementing the test application's actual login protocol.
RESTler requires a metadata line followed by complete token header lines; a
bare access-token string is not valid refresh output. For example:

```text
{u'app1': {}}
Authorization: Bearer FIXTURE_TOKEN_VALUE
```

```json
{
  "authentication": {
    "token": {
      "token_refresh_cmd": "python3 refresh_token.py",
      "token_refresh_interval": 1800
    }
  }
}
```
Verify the auth header is LIVE before trusting a clean run: a broken refresh command makes RESTler fuzz as anonymous and "find nothing".

### Step 3: Run Modes
```bash
# test: replay each request once — validates the grammar and auth
restler test --grammar_file ./Compile/grammar.py \
  --dictionary_file ./Compile/dict.json --settings restler_user_settings.json
# fuzz-lean: single-pass fuzzing with default payloads — fast baseline
# fuzz: full producer-consumer sequences — highest bug yield
restler fuzz-lean --grammar_file ./Compile/grammar.py \
  --dictionary_file ./Compile/dict.json --settings restler_user_settings.json
restler fuzz --grammar_file ./Compile/grammar.py \
  --dictionary_file ./Compile/dict.json --settings restler_user_settings.json --time_budget 8
```
Configure the desired checkers in the settings supported by the installed
RESTler version. The namespace checker requires two independently authorized
test identities with different private resources; one token cannot test
cross-tenant isolation. Confirm checker names and activation with that
version's `--help` and documentation rather than inventing CLI switches.

### Step 4: Custom Dictionary (app-specific bugs)
```bash
# Generate a JSON dictionary; JavaScript expressions are not valid JSON.
python3 - <<'PY' > dict.json
import json
from pathlib import Path

dictionary = json.loads(Path("Compile/dict.json").read_text())
dictionary.setdefault("restler_fuzzable_string", []).extend([
        "admin", "root", "1", "2", "12345", "' OR '1'='1'--",
        '{"$ne":"x"}', "../../etc/passwd", "\u0000", "A" * 10000,
])
dictionary.setdefault("restler_fuzzable_int", []).extend(["0", "1", "-1"])
print(json.dumps(dictionary))
PY
```
The compiler's other dictionary keys are preserved. After generating this
merged file, rerun the chosen mode with `--dictionary_file ./dict.json`.
Use `restler_custom_payload` for per-resource dynamic values in the grammar.

### Step 5: Triage Bug Buckets
```text
Per bug: request sequence + response in RestlerResults.
REQUIRES TRIAGE: 500s with stack traces (not automatically security impact).
CONFIRMED ONLY WITH IMPACT: NamespaceRule cross-tenant reads, UseAfterFree
      (deleted resource still returns 200/data), auth bypasses in sequences
NOISE: GC/timing races, expected 401s from token refresh gaps, soft validation 422s
Reproduce every real finding manually (outside RESTler) before reporting —
Xalgorix is verified-only.
```

### Step 6: Verify Coverage
```text
From RestlerResults/logs: covered endpoints vs total in the grammar.
Endpoints never exercised (dependency resolution failures, auth-limited
routes) are UNTESTED, not clean. Feed missing producer dependencies back
into the dictionary, or exercise those endpoints directly.
```

## Evidence Contract
A RESTler-derived finding requires:
1. The triggering request sequence (from the bug bucket)
2. A manual reproduction outside RESTler
3. A concrete outcome: crash with stack trace, cross-tenant data, use-after-free data, or injected payload effect

**NOT evidence**: a 500 that never reproduces, an empty bug-free run without verified auth/coverage, soft-validation rejections, 401 storms from a broken refresh

## Common Misses
- Auth-refresh broken mid-run → the whole run silently unauthenticated
- fuzz-lean only (single-pass) — no stateful sequences, missing the highest-value bugs
- Default dictionary only — app-specific payloads never tried
- Checker set empty — NamespaceRule/UseAfterFree/PayloadBody never ran
- Coverage never inspected — unresolved dependencies left endpoints "clean"

## False Positives / Non-Findings
- 422/400 validation rejections (input validation working)
- 401s during a token-refresh gap (auth noise, not a bypass)
- 500s that don't reproduce (GC/timing race)
- Timeouts on slow endpoints without other signals

## Xalgorix Tool Strategy
- `terminal_execute` for RESTler runs (compile/test/fuzz) and result triage
- Python for dictionary generation from recon-harvested values
- Manual reproduction via `http_request`/curl before any report

## Stopping Rule
Full fuzz (not just lean) on the highest-value services, all checkers enabled, custom dictionary seeded, coverage gap-free or explicitly documented.

## Handoff
Report each reproduced finding with the sequence, the manual repro, and the concrete outcome. Cross-tenant reads chain into api-bola; property abuse into api-bopla; injection effects into api-injection.
