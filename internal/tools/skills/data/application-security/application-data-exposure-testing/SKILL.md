---
name: application-data-exposure-testing
description: Distinguish real unauthorized data exposure from harmless metadata - response field differentials
  by role and tenant, over-fetching, alternate serializers and exports, error responses, notifications, audit
  logs, cached content - requiring meaningful confidentiality or authorization impact to report.
domain: cybersecurity
subdomain: application-security
tags:
- data-exposure
- information-disclosure
- over-fetching
- serializer
- pii
- differential
version: '2.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
intent: offensive
phase: application-testing
blackbox: true
---

# Application Data Exposure Testing

## Purpose

Applications leak data through many channels beyond "the endpoint returned a field": nested objects, alternate serializers, exports, error responses, notifications, audit logs, caches. Most such leakage is harmless metadata. This skill finds the subset with meaningful confidentiality or authorization impact - by asking, for every response, what THIS identity should have received versus what it actually received.

## Entry Conditions

- You can observe the same application object or operation from at least two identity contexts (roles, tenants, or anonymous)
- OR: the application has export/report/serialization surfaces beyond the primary API

## Differential Reasoning (the core method)

For every response channel:

```text
what should THIS identity receive for this object?
vs
what did it actually receive?
```

Concretely: fetch the same object as the legitimate owner, then as a different identity (authz_matrix automates the replay), and DIFF the payloads field by field. Fields present in the attacker-context response that belong to another principal are exposure. Fields that are merely descriptive of your own data are not.

## Exposure Channels

- Response fields: over-fetching on list/detail endpoints - objects returning MORE than the requesting context should see (other tenant names, internal pricing, admin notes)
- Nested objects: `invoice.customer.{address, phone, email}` where the requester should only see the invoice
- Alternate serializers: the JSON endpoint strips fields but the CSV/export/report/printer version does not (and vice versa) - compare ALL serializers of the same object
- Error responses: stack traces, raw SQL fragments, internal paths, user data inside validation messages ("user with email x@y already exists" - enumeration), debug parameters
- Exports / reports / downloads: generated files inherit the serializer of the export pipeline, frequently an older, leakier one; also check WHO can request the export (role) vs WHO the export covers (scope)
- Notifications / email previews: in-app notification previews and email digests often embed full objects the UI would filter
- Audit events / logs exposed through UI or API: activity feeds leaking actor identities, IPs, object names cross-tenant
- File metadata: uploaded-file records exposing original filenames, uploader identity, internal paths
- WebSocket messages: broadcast or misaddressed frames carrying other sessions data
- Cached content: CDN/browser-cached responses for authenticated objects (private data served from cache to another context)

## What Is NOT a Finding By Presence

```text
internal_id, uuid, debug, created_at, role, tech-stack hints, missing security headers
```

Opaque internal identifiers, timestamps, role names in YOUR OWN record, framework versions: these are metadata. They become findings only when chained into impact:

- `internal_id` becomes a finding when it enables cross-object access (combine with authorization-testing)
- `role` in someone ELSE record becomes a finding (that is over-fetch about another principal)
- debug/stack trace becomes a finding when it exposes data, credentials, or a usable internal topology
- enumeration via error message becomes a finding with a reproducible differential and a demonstrated consequence (mass account discovery, password-reset targeting)

The rule: an exposure is reportable when a real confidentiality boundary (identity, tenant, or privilege) was crossed, or the data enables a further attack with concrete steps.

## Methodology

```text
pick an object class (order, user, document, tenant)
-> fetch as the legitimate owner (baseline)
-> fetch the same object as: lower role, other tenant, anonymous (authz_matrix)
-> diff payloads field-by-field across ALL serializers (json, csv, export, error path)
-> for each extra field: whose data is it? can the receiver act on it?
-> demonstrate impact (read another tenant record, extract PII at scale, chain the id)
-> report with both payloads attached
```

## Evidence Contract

Not enough: "the API returned an internal_id field".
Good proof: the id (in the attacker-context response) resolves to another tenant object - re-fetch the object with that id in the attacker session and show the data returned.

Not enough: "user data found in the CSV export".
Good proof: a lower-privileged user exported a report containing other users emails/phone numbers, with the export request and a matching record from the owner context attached.

Not enough: "error message discloses stack trace".
Good proof: the trace contains a database connection string / internal endpoint / user PII, captured verbatim and shown to be attacker-triggerable.

## Common Misses

- Diffing only the primary JSON serializer - export/report/email channels are the leaky periphery
- Never diffing across roles for the SAME endpoint (over-fetch is invisible to a single-identity crawl)
- Ignoring notification/email-preview surfaces entirely
- Treating every present field as a finding (metadata noise dilutes the report and burns credibility)
- Forgetting cached variants: a CDN-cached authenticated page served cross-session

## False Positives

- Fields describing the REQUESTER own data (role, created_at on your own record)
- Opaque UUIDs that authorize nothing and resolve to nothing cross-identity
- Intentional cross-principal data (public profiles, shared workspace content)
- Enumeration-flavored errors that are actually rate-limited to uselessness - state the limit and the remaining impact honestly
- Framework/version banners without a demonstrated consequence

## Xalgorix Tool Strategy

- authz_matrix - automated same-object different-identity payload diffs (the core primitive here)
- http_request to fetch each serializer (Accept headers, format params, export endpoints)
- browser_action to confirm UI-rendered exposure and download flows
- record_hypothesis per (object x channel) with the expected-vs-actual field list; add_hypothesis_evidence with both payloads
- Chain: exposure primitive + authorization-testing to elevate ids into full cross-identity access proof

## When to Load a Specialist Skill

- Exposure that is actually broken access control -> authorization-testing (BOLA evidence pattern)
- Cache-layer exposure -> web-cache-deception / cache-poisoning
- Error-based enumeration feeding brute force -> the relevant authentication specialist
- Source-attached targets -> source-assisted-analysis (find the serializer the UI forgot)

## Stopping Rule

Stop when: each major object class has been diffed across available identities over at least two channels (primary API + one export/serializer), error/audit/notification channels have been sampled once each, and no new channel appears. Report the exposures that cross a confidentiality boundary with impact; record metadata observations as notes for chaining - do not report them standalone.

## Handoffs

- authorization-testing - most over-fetch findings ARE authorization findings; this skill proves the data arrived
- application-attack-surface-modeling - object/serializer inventory feeding this testing
- input-boundary-testing - when exposure is triggered by unexpected parameter shapes
