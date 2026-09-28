---
name: security-control-differential-testing
description: Find security-relevant interpretation gaps between layers - client, CDN, WAF, reverse proxy,
  API gateway, application, framework - using path normalization, method, encoding, header, and version
  differentials. The goal is a control that one layer honors and another ignores, not generic WAF bypass.
domain: cybersecurity
subdomain: application-security
tags:
- control-differential
- waf
- reverse-proxy
- path-normalization
- method-override
- api-gateway
version: '2.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
intent: offensive
phase: application-testing
blackbox: true
---

# Security Control Differential Testing

## Purpose

Requests pass through a stack - client, CDN, WAF, reverse proxy, API gateway, application, framework/router - and each layer interprets the SAME bytes slightly differently. A security control enforced at one layer but not another is a bypass. This skill hunts the differentials that CHANGE a security outcome, pairing each experiment with a control request so differences are attributable.

## The Layer Model

```text
Client -> CDN -> WAF -> reverse proxy -> API gateway -> application -> framework/router
```

Determine which layers exist first (response headers, Server/Via/X-Cache hints, cookie domains, error pages, timing on block). Not every target has every layer; test the handoffs you actually observe.

## Differential Experiments

Each experiment: send the CONTROL (canonical request) and the VARIANT; compare status, headers, body, and - critically - the OUTCOME (was the operation performed?). Use an operation you can verify server-side (an object read/write you can re-fetch).

### Path interpretation
- Trailing dot: `/admin.` vs `/admin`; trailing slash; double slashes `//admin`
- Encoded slash: `%2fadmin`, double-encoded `%252fadmin`
- Semicolon/matrix params: `/public;/../admin`, `/admin;x=1`
- Dot-segments: `/public/../admin`
- Case variation: `/ADMIN`, `/AdMiN`
- Unicode normalization: `/adm%u0069n` where the platform normalizes

### Method interpretation
- Verb swap: gateway authorizes GET, backend accepts POST/PUT/PATCH/DELETE on the same path
- Override headers: X-HTTP-Method-Override, X-Original-Method, X-Method-Override
- HEAD/POST bodies, OPTIONS leaks, arbitrary verbs (FOO) that fall through to route handlers
- Content-Type change: application/json vs form-encoded vs text/plain vs multipart delivering the same operation

### Header interpretation
- Duplicate headers (two Authorization, two Host, two Content-Length - where accepted)
- Conflicting headers (two different tenant IDs)
- Header case folding; whitespace variants (`X-Tenant-ID: a` vs ` X-Tenant-ID: a`)
- Host/X-Forwarded-For/X-Original-URL overrides where the app trusts forwarded headers

### Version/route interpretation
- Same operation via `/api/v1` vs `/api/v2` vs `/internal` vs GraphQL vs mobile endpoints - controls added to the new route family often miss the old one
- Alternate ports or direct backend addresses where in scope

## What Makes a Differential a Finding

The interpretation gap must CHANGE a security outcome:

```text
WAF sees /public      (no block)
backend sees /admin   (route executes)
=> blocked content reached: differential confirmed

gateway authorizes GET only
backend accepts arbitrary verb for the same write
=> the write succeeded through the variant: differential confirmed

JSON validator rejects duplicate keys at the gateway
backend parser uses the SECOND value
=> attacker-controlled second value took effect: differential confirmed
```

Not a finding by itself: the WAF can be bypassed for a request that the application then correctly rejects, or a path that reaches a public page anyway. A bypass primitive without a security-relevant target is an observation to chain, not a report.

## Methodology

```text
map the layers (what proxies/blocks/errors are observable)
-> choose a security-relevant operation you can verify (protected read, state change)
-> capture the canonical request (control)
-> apply ONE interpretation variant
-> compare outcome of control vs variant (status, body, AND backend effect)
-> if outcome differs, minimize which layer diverged (strip layers when possible)
-> report the differential with both requests and the divergent layer named
```

## Evidence Contract

Not enough: the WAF did not block variant X.
Good proof: the variant request performed/reached the operation the control exists to prevent - protected object returned, write persisted, auth check skipped - with the control request's rejection attached for contrast.

Always attach the CONTROL pair: the same request in canonical form showing what the enforcing layer does with it.

## Common Misses

- Testing bypass payloads against public endpoints - the differential only matters against a CONTROLLED operation
- Never re-fetching backend state (a bypassed write that did not persist is not an outcome)
- Ignoring which layer diverged - the report must name it, or remediation lands on the wrong box
- Skipping verb/override variants because "the UI only uses GET"
- Forgetting cache layers: a cached response for one path shape served for another (web-cache-deception class) is a differential outcome too

## False Positives

- Variant returns the same public content the control returns (no outcome change)
- 403 from a DIFFERENT layer than the control (e.g. app-level auth on the backend) - the gateway was never the enforcing layer
- Cosmetic differences (redirect to login, error styling) without an access or validation outcome difference
- Path variants that normalize to the same route and produce identical responses - parser agreement, the healthy case

## Xalgorix Tool Strategy

- http_request for exact control/variant pairs (raw paths, headers, and bodies; keep the pair byte-identical except the variant)
- browser_action to confirm outcome differences that require execution (redirects, JS-driven flows)
- authz_matrix to verify the operation is otherwise protected (the control baseline)
- record_hypothesis per (layer x variant); add_hypothesis_evidence with BOTH requests
- verifiers once the differential exposes a class signal (verify_sqli, verify_ssrf, verify_path_traversal on the newly reachable sink)

## When to Load a Specialist Skill

- WAF bypass technique depth -> performing-web-application-firewall-bypass
- Protocol-level desync between proxy pairs -> http-request-smuggling
- Cache-layer abuse -> cache-poisoning / web-cache-deception
- Authorization outcome of the differential -> authorization-testing (this skill proves the bypass; that skill proves the access break)

## Stopping Rule

Stop when: the observed layers each have one representative experiment per category (path, method, header, version), each controlled operation was tested with its most-likely variant rather than every variant, and two consecutive experiment rounds produce no new interpretation divergence. A proven differential on one operation should be re-tested on ONE other operation to confirm generality - not on every endpoint.

## Handoffs

- authorization-testing - what the bypassed control was protecting
- input-boundary-testing - parser-confusion variants discovered here become parameter-level hypotheses
- web-application-security specialists - once the differential exposes a concrete vulnerability class
