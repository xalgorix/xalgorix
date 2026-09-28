---
name: file-processing-pipeline-testing
description: Model and attack the full file processing pipeline - upload, validation, storage, transformation,
  scanning, preview, import, processing, serving - hunting parser confusion, archive extraction abuse,
  traversal, decompression issues, access-control gaps between stages, and content-type mismatches.
domain: cybersecurity
subdomain: application-security
tags:
- file-upload
- file-pipeline
- parser-confusion
- archive-extraction
- polyglot
- content-type
version: '2.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
intent: offensive
phase: application-testing
blackbox: true
---

# File Processing Pipeline Testing

## Purpose

"Can I upload a .php?" is one question about one stage. Real breakage happens BETWEEN stages: the validator accepts what the parser executes, the transformation library trusts what the upload validator rejected, the storage layer exposes what the application hides. Model the whole pipeline, then test every stage boundary and every trust handoff.

## The Pipeline Model

```text
upload -> validate -> store -> transform -> scan -> preview -> import -> process -> serve/download
```

Map which stages exist for YOUR target (not all do): is there a preview generator, a thumbnailer, a virus-scan step, an import parser, a download/share endpoint? Each arrow is a trust handoff where one stage assumptions about the file may no longer hold.

## Stage-by-Stage Testing

### Upload / validation boundary
- Filename: path segments, traversal (`../../`), reserved names, unicode lookalikes, very long names, null bytes, case variants (`.PNG`, `.pHp`), double extensions (`report.pdf.php`), trailing dot/space (`file.php.`, `file.php `)
- Extension vs MIME vs magic bytes disagreement: declare `image/jpeg`, send PHP bytes with `.jpg` extension; note WHICH check each endpoint trusts
- Polyglots: GIF/JPEG containing embedded code, PDFs with JS, SVG with embedded scripts (SVG is XML: scripts and XXE live inside), HTML-in-image (served with wrong content-type becomes stored XSS)
- Content-Type the server assigns at STORE time vs at SERVE time (mismatch is the exploitable condition)

### Storage
- Where does the file land: same-origin path (execution risk), CDN/object storage, separate storage domain?
- Is the stored object accessible directly (guessable URL, sequential name) BEFORE the app links it?
- Storage-level ACL: can the raw object be fetched unauthenticated once the URL is known?
- Overwrite: does uploading with the same name/fingerprint overwrite another user object (hash-collision namespaces)?

### Transformation (the highest-value stage)
- Image conversion (ImageMagick-style), PDF processing, document conversion, media transcoding, thumbnail generation - each pulls a complex parser with its own vulnerabilities
- Parser differentials: file the VALIDATOR parses as JPEG but the TRANSFORMER parses as something else (polyglots shine here)
- Image format-specific payloads (MVG/EPHEMERAL-style operator abuse where transformation libraries are in use), XXE in XML-based formats
- Crash/DoS observation: a transformation that hangs or crashes is a robustness finding, not a code-exec finding - say what it is

### Archive extraction (import/unzip stages)
- Path names inside archives: zip-slip (`../../` entries), absolute paths, windows drive letters
- Decompression bombs (nested archives) - bounded resource abuse observation
- Symlink entries in tar archives pointing outside the extraction root
- Archive-format parser differentials between two libraries (validator inspects with one, extractor uses another)

### Import / server-side fetch
- Import-by-URL: does the server fetch attacker-supplied URLs? -> SSRF primitive (hand off to ssrf specialist); internal address blocks must be tested against every fetch variant
- CSV/JSON/XML import: injection into downstream consumers, formula injection in spreadsheet exports/imports (cells starting with = + - @), XXE in XML import
- Metadata ingestion: EXIF/author fields stored and later rendered unescaped -> stored XSS primitive

### Serve / download
- Who can fetch the file: object-level authorization on download endpoints (authz_matrix on the file id)
- Content-Type/Content-Disposition at serve time: inline vs attachment, charset, `X-Content-Type-Options` absence
- Cached content, signed URLs: expiry and scope of the signature
- Response header reflection making stored content execute in the origin context

## Evidence Contract

Not enough: the file uploaded successfully.
Good proof per class:
- Execution: the stored file executed or its content influenced server behavior (OOB callback, computed template output)
- Stored XSS: a second user (or the same user in the origin context) renders attacker script - browser-verified
- Traversal/overwrite: the file (or extracted archive entry) exists at a path outside the upload root - prove with a read or an observable side effect
- SSRF: the internal fetch is observed at the attacker-controlled callback or via a timing/state differential
- Access-control: a different identity downloads the file via authz_matrix differential
- Content-type mismatch: the dangerous content renders/executes because of the SERVE headers, captured in the browser

## Common Misses

- Testing only the upload endpoint and never the serve/preview/download side (where stored content actually executes)
- Skipping the transformation stage entirely (thumbnailers/converters are the most fragile parsers)
- Not testing archives when an import/unzip feature exists
- Assuming the client-side uploader constraints reflect server validation
- Forgetting metadata as a stored-XSS vector into admin galleries/reports
- Not re-checking authorization at the DOWNLOAD step (upload checks often differ from download checks)

## False Positives

- Upload accepted + file stored + served correctly with attachment disposition and correct type = working pipeline, not a finding
- A polyglot stored but never rendered/executed anywhere = weak observation; record it, chain it only when a render/execution sink exists
- Virus-scan flagging your test file = the control working
- ImageMagick-style operator payloads without evidence the transformation library processes that format = hypothesis, not finding

## Xalgorix Tool Strategy

- browser_action to drive real upload flows and observe preview/render behavior (stored XSS verification included)
- http_request for raw multipart upload replays and download fetches across identities
- authz_matrix on file/object download endpoints (upload-vs-download authorization differential)
- verify_oob for blind execution/SSRF confirmation; verify_xxe on XML-based import; verify_path_traversal on extraction targets
- record_hypothesis per stage-boundary suspicion; add_hypothesis_evidence with the exact file/headers used

## When to Load a Specialist Skill

- Webshell/extension-based upload exploitation depth -> exploiting-file-upload-vulnerabilities
- SSRF technique -> ssrf; XXE technique -> xxe; stored XSS -> xss; traversal -> path-traversal-lfi-rfi
- Command injection in conversion pipelines -> rce
- Race on the same file object -> race-condition-testing

## Stopping Rule

Stop when: every pipeline stage the target actually has has been mapped, each trust handoff (validate->store, store->transform, transform->serve) has been crossed with at least one hostile input class, download-side authorization has been tested once per file object class, and no new stage (preview, import, fetch-by-URL) has appeared. Pursue proven crossings to impact; do not enumerate every polyglot variant when one stage already proved permeable.

## Handoffs

- authorization-testing - object-level access on stored files
- application-data-exposure-testing - files reachable by parties who should not have them
- input-boundary-testing - metadata/CSV/XML content as hostile input into downstream parsers
