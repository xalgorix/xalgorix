---
name: source-assisted-analysis
description: Use attached source code as a SECONDARY accelerator for black-box testing - work the auto-seeded
  source-to-route ledger first, trace call paths before claiming a sink is reachable, find hidden routes and
  extra hypotheses, and correlate confirmed runtime behavior back to code. Black-box remains primary.
domain: cybersecurity
subdomain: application-security
tags:
- whitebox
- source-assisted
- code-review
- sast-leads
- hypothesis-generation
version: '2.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
intent: offensive
phase: source-analysis
blackbox: false
whitebox: true
---

# Source-Assisted Analysis (Secondary Accelerator)

## Purpose

When source is attached, use it to generate leads, prioritize, and explain - NOT as a replacement for runtime proof. Xalgorix stays a black-box-first product: the application model and hypotheses come from runtime behavior; source accelerates and strengthens them.

```text
BLACK BOX (primary)                    SOURCE WHEN AVAILABLE (secondary)
application model                      additional leads
-> hypotheses                           -> source-to-runtime correlation
-> runtime testing                      -> higher confidence / faster testing
```

NOT: source scan -> everything else. The only exception is an explicit source-review-only scan mode, which continues to work as before.

## Entry Conditions

- Source code is attached to the scan (the source sweep at scan start seeds the ledger with correlated source-route hypotheses)
- OR: runtime behavior is surprising and the attached source can explain it

## What Source Is For

1. **Hidden routes and surface**: routes the crawler never found (internal/debug/deprecated controllers) - add them to the model as runtime-verified inventory
2. **Additional hypotheses**: dangerous handlers, parameters, and flows the black-box crawl did not prioritize
3. **Prioritization**: which observed endpoints sit near dangerous sinks - rank the black-box queue by this
4. **Explaining surprises**: when a runtime response is odd (unexpected parser behavior, weird error), trace it to code to understand what actually happened
5. **Strengthening evidence**: correlate a confirmed runtime finding to the code path that produces it - the report becomes harder to dispute
6. **Sink discovery beyond the crawl**: sinks reachable only through parameters/flows the UI does not expose

## The Seeded Ledger (Work It First)

At scan start the source sweep already seeded the hypothesis ledger: a route whose handler holds a dangerous sink is seeded CLASS-TYPED (rce/sqli/ssrf/...) at high confidence. These correlated source-to-route leads are the highest-value first targets:

1. CLAIM: claim_next_hypothesis (optionally vuln_class=...) takes the top correlated lead; read_ledger lists all. If the ledger looks empty, run scan_source_sinks then scan_source_routes to reseed from the code.
2. PROBE: probe_hypothesis the lead - confirm the route is LIVE and reachable on the target (it reuses the scan session, so authenticated routes are probed authenticated).
3. VERIFY: confirm the class deterministically (verify_sqli, verify_ssti, verify_xss, verify_oob, verify_timing, ...) - each records exploit-proven evidence.

A seeded hypothesis is still a HYPOTHESIS: prove it at runtime before reporting.

## Call-Path Discipline (the main correctness rule)

A dangerous sink several calls away from the route:

```text
route -> controller -> service -> repository -> dangerous sink
```

Same-file or same-handler proximity does NOT prove the route reaches the sink - and distance does NOT prove safety. Before claiming a source-to-sink path:

- follow the actual call chain: imports, function calls, service methods, helpers, repository methods, callbacks, async jobs
- verify each hop with code_search (query the callee, confirm the parameter flows through, watch for guards/sanitizers BETWEEN route and sink)
- then confirm the path at runtime with a probe (the route is live, the input reaches, the sink fires)

Source proximity is a LEAD QUALITY signal, not evidence. Runtime confirmation is evidence.

## Guard/Sanitizer Reading

When a sink appears guarded, read what the guard actually enforces:
- Validation applied to which parameter shapes? (a guard for strings that misses arrays/objects - input-boundary-testing overlap)
- Is the check before EVERY write path or only one entry point (multiple callers)?
- Is the sanitizer encoding for one context but rendered in another (HTML-escape that misses a JS/attribute context)?
- Centralized middleware vs per-route checks - find the routes that MISS the middleware

## What Not to Do

- Do not turn the scan into a SAST report: source findings without runtime confirmation are NOT findings (except in source-review mode, which has its own contract)
- Do not report "dangerous function present in codebase" - every large codebase contains sinks
- Do not trust reachability by file proximity alone
- Do not skip runtime validation because "the code obviously does it"

## Xalgorix Tool Strategy

- scan_source_sinks / scan_source_routes - seed and reseed the correlated ledger
- code_search - trace call paths hop by hop (query, glob, path, sinks, max parameters); use it for the guard-reading workflow too
- claim_next_hypothesis / probe_hypothesis / read_ledger - work the seeded leads
- http_request / browser_action / deterministic verifiers - all runtime confirmation stays black-box-first
- add_hypothesis_evidence - attach the code citation ALONGSIDE the runtime proof, not instead of it

## Evidence Contract

Not enough: "code_search found an exec() call in upload.go".
Good proof: the exec-containing route is live on the target, a crafted request reaches it (captured), and the command execution effect is observed (verifier or OOB callback) - with the call path (route -> handler -> exec) cited from code as supporting evidence.

Not enough: "the sanitizer in utils.go is weak".
Good proof: a runtime request passing the weak guard produces the class effect, with both the request and the verifier verdict attached.

## Stopping Rule

Stop source work when: the seeded ledger is exhausted (claimed and closed every correlated lead), the call paths for observed routes have been traced once, and no new hidden route or dangerous handler appears from two further code_search passes. Return to black-box coverage - the source served its purpose as accelerator.

## Handoffs

- application-attack-surface-modeling - feed discovered routes/sinks into the runtime model
- input-boundary-testing - guards that miss parameter shapes become boundary hypotheses
- web-application-security specialists - once a class signal is live, the specialist skill owns the exploitation depth
