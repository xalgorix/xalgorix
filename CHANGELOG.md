# Changelog

## Unreleased

### Fixed
- **Content discovery no longer fails when SecLists is absent or installed with different capitalization.** Before launching `ffuf`, `gobuster`, `feroxbuster`, `dirsearch`, `dirb`, or `wfuzz`, terminal execution now resolves the requested list suffix across both case-sensitive `SecLists`/`seclists` spellings and common distro locations. If no host list exists, Xalgorix atomically materializes a compact embedded web-discovery list under the scan-local `tmp/wordlists/` directory, rewrites only literal missing system paths, preserves ffuf `:KEYWORD` suffixes, and reports the substitution in the tool result. Existing, generated, relative, and variable-based lists remain untouched.
- **Malformed MiniMax/tool-protocol output can no longer masquerade as a successful scan.** Provider control-token leaks such as `<]minimax[>` and bare `<tool_call>` fragments are discarded instead of being shown or fed back into model history, receive an immediate canonical XML recovery prompt, and stop after a bounded backoff rather than spending 30 rapid calls in a corruption loop. An unrecovered specialist is now reported to its coordinator as `FAILED` with `llm_malformed_tool_output` (without poisoning the root session), generic no-tool force-stops are marked abnormal rather than clean, whitespace-only responses use the empty-response recovery path, and MiniMax never receives the scanner's invalid zero-temperature override. Root completion messages prefix the authoritative persisted finding count so model-written summaries cannot turn 23 stored findings into a claimed 24.
- **Equivalent same-origin findings now deduplicate across the URL forms agents use during long scans.** A relative endpoint and its full absolute URL share one semantic key, a scheme-less target matches the same explicit host/port, path placeholders remain decoded, and explicit scheme or non-default-port differences remain isolated. This collapses repeat `/eval`, `/uptime`, `/tokens`, and `/user/{user}` reports without merging distinct services.
- **Full scans now launch one deterministic specialist wave after the coordinator has established recon, a plan, and a populated evidence ledger.** The root agent delegates the authorization/business-logic, server-side injection, and client/source lanes once (from iteration five onward), while discovery/recon scans and child agents remain non-delegating. The graph enforces a three-child lifetime cap, preventing nested or repeated waves, and each lane receives a private `tmp/<role>/` scratch directory so concurrent specialists cannot overwrite one another's artifacts.
- **Known-CVE findings no longer disappear from real-world benchmark scores because the model omitted optional metadata.** An exact CVE identifier plus the expected endpoint family and exploit proof now remains authoritative when `cwe_id`, class metadata, or the optional method is absent; an explicitly wrong method, unrelated endpoint, different CVE, or unproven report still fails. The reporting pipeline also fills an omitted target only when the active scan has exactly one canonical target, and deduplicates the same CVE on that target even when agents use different proof endpoints.
- **Inflated integrity/availability claims are now corrected without dropping an otherwise proven vulnerability.** Complete CVSS 3.0/3.1 vectors are parsed and scored deterministically; unsupported `I:H`/`A:H` impact is normalized to `L` when limited impact is demonstrated or `N` when it is not, negated phrases such as “no state change” cannot count as proof, and the vector-derived score/severity becomes authoritative. An arbitrary file read therefore persists as the evidence-backed `C:H/I:N/A:N` (7.5 High) instead of being rejected or stored as 9.8 Critical. The original vector, score, and severity remain in the result audit metadata. Valid proof that explains an artifact is “not a placeholder” is also no longer rejected merely for containing the word `placeholder`; explicit simulated/placeholder findings remain blocked.
- **Isolated benchmarks reject host-wide scratch exploration and host-global cookie/config files.** Broad `find /` / `du /` traversal is blocked while bounded security wordlists remain available, and curl cookie/config flags may not read or write host `/tmp`; agents are directed to the scan-local project `tmp/` tree instead. Release artifacts now use the repository's ignored `tmp/xalgorix-release/` directory for the same isolation guarantee.
- **Coverage is now tracked per endpoint and vulnerability class instead of being inferred from unrelated global activity.** Testing SQL injection on one route, or merely touching another route with a generic request, no longer marks every endpoint/class pair as complete. Grouped plan tasks close only after every discovered endpoint has exact evidence for the requested class, including independently scoped hosts that share the same path. This prevents premature plan completion and returns scan time to the surfaces that were previously skipped.
- **Delegated specialists can finish their bounded assignment after meaningful security testing.** Specialists no longer inherit the root coordinator's full-recon and five-shell-command finish gates, which caused completed subagent plans to loop for hundreds of iterations while the coordinator repeatedly timed out. The root scan retains its existing depth gates; delegated agents must still perform a meaningful security action and complete their own plan.
- **Specialists must exhaust their entire assigned lane instead of stopping after the first proven bug.** Each role now repeatedly claims and closes every assigned hypothesis, reports and links every distinct proven vulnerability, rejects safe leads with baseline evidence, and verifies that no claimed work remains before finishing. Executed endpoint/class coverage is shared across the scan, so work performed by a specialist immediately reconciles the coordinator's plan instead of being lost in per-agent state.
- **Malformed named parameter closing tags from LLM tool calls are repaired before parsing.** Responses such as `<parameter=title>...</title>` are normalized to the expected `</parameter>` form, preventing endpoint, severity, and target fields from being swallowed into vulnerability titles and improving stable finding identity between repeated scans.

### Added
- **A reproducible real-world CVE benchmark mode measures recall, fixed-version regressions, and run-to-run stability.** The benchmark runner accepts strict versioned manifests, pinned container digests, proof-bearing expected findings, loopback-only targets, repeated independent runs, and a fixed control. The initial fixture compares vulnerable Grafana 8.2.6 with patched 8.2.7 for CVE-2021-43798 through an isolated ingress and reports per-CVE match rate plus mean/min/max recall.
- **Real-world benchmark stability is a hard acceptance gate.** A run now fails unless every documented vulnerability is matched in every repetition and every patched-control repetition stays clean, so intermittent recall cannot pass by averaging one lucky run with misses.

## [v4.6.66](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.66) — LFI → RCE via log/session poisoning (2026-09-05)
### Changed
- **The agent now escalates a Local File Inclusion into remote code execution via log/session poisoning when a direct read is blocked, instead of giving up.** Many real LFIs cannot be read directly: the target is a `.php` file (PHP `include()` executes it, so a bare `<?php ... ?>` prints nothing) or the sink prepends a fixed directory to the input (which defeats the `php://filter` wrapper). The escalate-to-flag playbook now teaches the standard advanced techniques for these cases — poison a web-server log by sending a PHP snippet in the `User-Agent`/`Referer` header then LFI-include the log (`/var/log/apache2/access.log`, `/var/log/nginx/access.log`) so it executes; poison a PHP session file (`/var/lib/php/sessions/sess_<id>`); `/proc/self/environ`; and the `php://filter` iconv filter-chain RCE generator — then read the target file (e.g. `cat /FLAG.php`) to recover its contents even when it is itself PHP. A challenge hint like "read poisoned files" maps directly to this. Behavioral (prompt) change; no tool/API changes.
## [v4.6.65](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.65) — Deeper flag-capture exploitation: XSS execution, SSTI/cmdi/LFI escalation, IDOR enumeration (2026-09-05)
### Changed
- **The agent now escalates a confirmed injection into an actual data/flag read instead of stopping at a proof-of-concept, and drives XSS to real execution — measured against the XBOW validation benchmarks.** Concretely: (1) the reflected-XSS methodology now uses auto-firing vectors (`img onerror`, `svg onload`, `body onload`, `autofocus onfocus`, `details ontoggle`, `video`/`iframe`/`marquee`) that execute in a headless checker, treats `confirm()`/`prompt()` and obfuscated forms as bypasses when a sink like `alert` is filtered, uses the exact string an oracle requires, and reads the response for a success/flag oracle rather than only checking reflection; (2) a new "escalate to code-exec/file-read, then read the flag" playbook drives SSTI to RCE via Jinja2 globals gadgets (with `attr()`/index/hex filter bypasses and Twig/Freemarker/SpEL equivalents), command injection to reading the target file at common/hinted paths (with blind redirect-to-web-path / time-based / OOB fallbacks), and LFI to `php://filter`/traversal reads; (3) PHASE 8 IDOR guidance now authenticates first, enumerates object/user IDs from id=1 (first/admin) and the caller's neighbors, and reads each object for the flag instead of only confirming an access differential; and (4) the agent is told not to abandon a signposted class for unrelated recon. On the 104 XBOW validation benchmarks this raised the pass@1 flag-capture rate from 58/104 to a projected ~70/104 (XSS +6, IDOR +2, SSTI +2, cmdi +2). Behavioral (prompt + skill) change; no tool/API changes.

### Added
- **A `cors` class and a credentialed cross-origin challenge extend the benchmark to CORS misconfiguration**, a pervasive real-world API bug. The new `cors-credentialed-reflect` challenge exposes an `/api/account` endpoint that reflects *any* request `Origin` into `Access-Control-Allow-Origin` while also setting `Access-Control-Allow-Credentials: true` — the classic exploitable pattern (reflected origin + credentials, not a harmless wildcard) — so a page on any attacker origin can make a credentialed cross-origin read of the victim's authenticated data (an email + `api_token`). The `safe-cors` negative control allows credentialed reads only from a single fixed trusted origin and never reflects an arbitrary caller `Origin`, so an over-reporting scanner fails it. The scorer recognizes `cors` via a specific text signal (`CORS` / `cross-origin resource sharing` / `access-control-allow-origin`) checked **before** the CWE — because agents often tag a CORS finding with a generic access-control CWE (e.g. CWE-284) that would otherwise fold it into `idor` — plus CWE-942/346. Operator-only benchmark tooling; the shipped binary is unchanged.
## [v4.6.63](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.63) — Benchmark: NoSQL injection (operator-injection auth bypass) class + challenge (2026-09-04)

### Added
- **A `nosqli` class and a NoSQL operator-injection challenge extend the benchmark to NoSQL auth bypass**, common in modern Node/Mongo stacks. The new `nosqli-auth-bypass` challenge exposes a `/api/login` that feeds the request's password straight into a Mongo-style query, so an operator payload — JSON `{"$ne": null}` or the bracketed form `password[$ne]=` — matches any password and authenticates without knowing it; normal wrong credentials are rejected (401), so the operator injection is the only way in. The `safe-login` negative control validates that credentials are plain strings and rejects operator objects with 400. The scorer recognizes `nosqli` (CWE-943 plus keywords like "nosql injection", "operator injection", "$ne"/"$gt"/"$where"), with the keyword row deliberately ordered before SQLi because "nosql injection" contains the substring "sql inject" (which would otherwise misclassify it as SQLi). Operator-only benchmark tooling; the shipped binary is unchanged.

### Fixed
- **A rate-throttled full-port `nmap` scan is now blocked before it runs and redirected to a bounded scan.** When a request-rate limit is active, the rate policy correctly injects `--max-rate`/`--scan-delay` into recon commands — but if the agent also asks for a full sweep (`nmap -p-`), that scans all 65,535 ports at the throttled rate, which takes **hours** and consumed an entire scan's turn/time budget on recon before any vulnerability testing happened (observed twice). A deterministic `OnToolCall` guard now force-skips a full-port nmap scan that carries a `--scan-delay` or a low `--max-rate` and tells the agent to re-run it bounded (`nmap -sV -sC --top-ports 200 --open TARGET`, adding specific extra ports only when there's a concrete reason); a matching CRITICAL RULE reinforces it. A fast, un-throttled `-p-` scan and any bounded `--top-ports` scan are unaffected. This returns the wasted budget to actual detection on every rate-limited scan.

### Added
- **A `business_logic` class and a price/quantity-tampering challenge give the benchmark its first business-logic coverage.** Business-logic flaws are among the highest-impact real-world bugs but had no class in the scorer at all (such a finding classified to nothing and could never be scored). The scorer now recognizes `business_logic` (CWE-840/841, plus keywords like "business logic", "negative quantity/price/total", "price/quantity tampering", "store credit", "workflow bypass"), and the new `business-logic-negative-qty` challenge exposes a `/checkout` endpoint that computes `total = quantity × price` with no check that quantity is positive — so a negative quantity yields a negative total the store still "places" (a refund/credit exploit). The item is HTML-escaped and the quantity is integer-parsed, so the only signal is the negative total (no injection red herring); the `safe-checkout` negative control rejects non-positive quantities with 400. Validated with the real agent: it read the business-logic/price-tampering skills, probed negative/zero/overflow quantities, and reported the flaw (which the scorer classifies as `business_logic`). Operator-only benchmark tooling; the shipped binary is unchanged.

### Added
- **A BFLA (Broken Function Level Authorization) challenge measures vertical privilege escalation**, the sibling of the v4.6.58 BOLA challenge and OWASP API #5. The new `bfla` challenge exposes an admin-only user-list function (emails + SSN fragments) that checks authentication but never the caller's ROLE, so a regular user (role B) receives the same privileged response as the admin (role A) — the authorization matrix flags the cross-identity match as broken access control, while anonymous is refused. The `safe-bfla` negative control enforces the role check (regular users get 403) so an over-reporting scanner fails it. Reuses the two-account benchmark harness; scores under the `idor` class (BFLA canonicalizes to idor). Operator-only benchmark tooling; the shipped binary is unchanged.

### Changed
- **A BOLA/IDOR flaw that `authz_matrix` deterministically confirmed now reports as exploit-proven instead of "needs manual verification", and the agent is steered to use `authz_matrix` in the first place.** Object-level authorization is the highest-value real-world class, but two gaps undercut it: (1) `authz_matrix` records the cross-identity access differential as ledger evidence, yet the report flow only recognized `verify_*` confirmers — so a genuinely confirmed BOLA fell back to the LLM re-verifier, which routinely can't reproduce it (it has no second session) and left the finding flagged for manual review; and (2) the phase playbook never told the agent to run `authz_matrix`, so it hand-rolled multi-account `curl` comparisons instead. Now the report flow recognizes an `authz_matrix` confirmation for the idor class — but only its **high-confidence** signal (a lower identity receiving the *same* successful response as the authorized one, i.e. "broken access control"); its weaker "accessible while the baseline was not successful — verify" heuristic is deliberately not treated as proof, since that can be the other identity's own object. PHASE 8 now leads with "confirm with `authz_matrix` first" the moment an object-id parameter or authenticated endpoint appears, and PHASE 20 routes IDOR/BOLA and auth-bypass/BFLA to it. A positive disproof from the independent verifier still drops the finding, so this cannot resurrect a false positive.

### Added
- **The benchmark can now host authenticated, two-account challenges, and a real BOLA (Broken Object Level Authorization) challenge exercises them.** Until now every challenge was single-user, so the benchmark could only measure unauthenticated IDOR — not the object-level authorization flaws that dominate real API bug bounty. A `Challenge` can now declare an `Auth` (role A, plus a second account role B); the harness wires role A as the scan's session and role B as the authorization matrix's comparison identity (mirroring production `XALGORIX_TARGET_AUTH` / `_B`). The new `bola` challenge serves every order to any logged-in user with no per-object ownership check, so replaying role A's own request as role B returns role A's data — the definitive BOLA signal — while anonymous is refused; the `safe-bola` negative control enforces ownership (403) so an over-reporting scanner fails it. Operator-only benchmark tooling; the shipped binary is unchanged.

### Fixed
- **The OAuth-`state` false-positive gate no longer drops a real CSRF finding just because it mentions "state".** The gate exists to reject the common non-issue of an OAuth *authorization endpoint* echoing `state=test` (the `state` parameter is validated by the client app, not the auth/server, per RFC 6749 §10.12). But its trigger was `"csrf" + "state"`, which also matched an ordinary CSRF on a **state-changing** action — the natural way to describe any CSRF, and exactly the wording `verify_csrf` emits in its own confirmation ("accepted a state-changing POST …"). A deterministically confirmed CSRF could therefore be rejected before it was ever reported. The gate now requires an actual OAuth/authorization context (or a distinctive OAuth-state phrase like "state parameter"/"state validation") to fire, so genuine cookie-auth form CSRFs pass while the OAuth authorize-endpoint false positive is still caught. Regression tests cover both a plain state-changing CSRF and the verbatim `verify_csrf` wording.

### Fixed
- **A finding a deterministic verifier already confirmed is now reported as exploit-proven instead of being flagged for manual review.** Each confirmer (`verify_sqli` / `verify_ssti` / `verify_xxe` / `verify_csrf` / `verify_xss`) records exploit-proven evidence in the scan ledger on a positive baseline-vs-probe differential, but only XSS had a bridge folding that proof into the report; every other class fell back to the independent LLM re-verifier, and whenever that was inconclusive (routine for CSRF and SSTI, which need cross-site/state or template context it lacks) the genuinely confirmed finding was stamped `Verified: false` / `needs-manual-verification` — undercutting the very confirmer that proved it. The report flow now recognizes a verify_*-recorded confirmation for the finding's class (matched by the verifier hypothesis origin, or by a `CONFIRMED` exploit-evidence summary so it survives ledger dedup merging the confirmation onto a prior probe hypothesis), folds it into the exploitation proof, and marks the finding exploit-proven. A positive **disproof** from the independent verifier still drops the finding, so this only rescues the inconclusive/absent-verifier case and cannot resurrect a false positive. This makes the whole confirmer family produce independently-evidenced, trustworthy findings end to end — the state a black-box user sees on the dashboard.

## [v4.6.55](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.55) — Stop polling dead OOB callbacks; pivot to in-band (2026-09-04)

### Changed
- **`oob_callback action=poll` now escalates after repeated empty polls and tells the agent to stop.** Filtered egress is common on real targets, and unbounded out-of-band polling is a recurring black-box budget sink — one real scan burned ~18 probes for zero callbacks, and a benchmark run polled a dead token over and over instead of reporting the finding it already had. The tool now tracks consecutive empty polls per callback token: after a few it warns that egress may be filtered, and past a hard threshold it returns a STOP directive steering the agent to in-band confirmation (differential timing / error-based via `verify_sqli`, a reflected internal resource returned by the target) or to drop the blind lead and move to the next-ranked surface. The counter resets when a callback finally lands, and the per-token map is bounded so a long-lived server process cannot grow it without limit. This returns wasted turns to detection and reporting on egress-filtered targets — exactly where recall was being lost.

### Changed
- **The assessment methodology now steers the agent from a positive probe straight to the matching deterministic verifier**, closing a real black-box conversion gap. The confirmers (`verify_sqli` / `verify_ssti` / `verify_xss` / `verify_xxe` / `verify_csrf` / `verify_oob`) were always registered and callable in a black-box active scan, but the phase playbook the agent actually follows only ever pointed at `sqlmap`/`dalfox`/manual `curl` and never named them — so on a real target the agent probed a parameter many times yet never ran the one-call confirmer and reported nothing. PHASE 6 (injection testing) now says to call the matching verifier the moment a parameter shows a class signal, with scanners demoted to the fallback when a verifier cannot confirm; PHASE 20 (exploit verification) maps each class to its verifier (`SQLi→verify_sqli`, reflected/DOM `XSS→verify_xss` — including POST params via `data=`, `SSTI→verify_ssti`, `XXE→verify_xxe`, `CSRF→verify_csrf`, blind→`verify_oob`) and routes LFI straight to `report_vulnerability` with the in-band `/etc/passwd` body (there is no LFI verifier). This turns probes the scanner already runs into independently verified, reported findings, which is where black-box recall was being lost.

### Added
- **`verify_xss` now confirms POST-based reflected XSS**, not just GET. Pass the form action as `url` and the request body as `data` (a urlencoded form body such as `search=<payload>`); `method` defaults to `POST` whenever `data` is present. The verifier stages a self-submitting, cross-origin form and lets the browser perform a real top-level POST navigation, so the response renders as a document and a POST-reflected payload actually executes — exactly as it would for a victim, which a `fetch()`/XHR can never reproduce. The execution oracle is unchanged (a dialog/console/DOM marker carrying the nonce), so the verdict stays proof-of-execution, and a confirmation records the same browser-origin CWE-79 evidence the reporting bridge already folds into findings.

### Fixed
- **Removed the biggest black-box budget sink on form-driven targets.** Because `verify_xss` was GET-only, a reflected XSS reachable only through a POST form could not be confirmed with the tool, so the agent hand-drove the confirmation with dozens of `browser_action` steps (and often hand-rolled scripts) — on one real target that single gap consumed the large majority of the scan's tool budget and still failed to produce an independently verified finding. POST-based reflected XSS now confirms in a single `verify_xss` call, returning that budget to broader probing and reporting.

### Added
- **`verify_csrf`, a Cross-Site Request Forgery confirmer** — the last member of the deterministic verifier family (`verify_sqli` / `verify_ssti` / `verify_xss` / `verify_xxe` / `verify_oob`), so every common injectable or forgeable class now has a one-call path that records exploit-proven evidence. Given a URL (or ledger hypothesis) and the state-change body, it replays the request the way an attacker's page would — a forged `Origin`/`Referer` and no anti-CSRF token, reusing the scan session's cookies — and confirms CSRF when the server accepts it (2xx/3xx with no token/forbidden rejection). It records CWE-352 evidence in the ledger and does not auto-report. It is deliberately production-safe: it **declines** when the endpoint is protected by an `Authorization` header (Bearer/Basic), which a cross-site attacker's browser never attaches, so it will not false-positive on token-auth APIs. Same safety envelope as the other verifiers (internal-host scope check, request-rate gate, no redirect following, disabled in passive mode).

## [v4.6.51](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.51) — Stop wasting scan turns on malformed update_plan calls (2026-09-03)

### Fixed
- **`update_plan` no longer rejects calls that omit `task_id` or `status`** — a shape models emit often, where each rejection previously burned a whole scan iteration on a "missing required parameter" error (a single benchmark run wasted ~13 turns this way, budget that then never reached detection and reporting). Plan status is advisory bookkeeping that never gates a finding, so the tool now infers safely: an omitted `status` defaults to `active`, and an omitted `task_id` applies to the single currently-active task (or the next pending task when marking one active), asking for an explicit id only when genuinely ambiguous. The status vocabulary is also more forgiving (`in_progress`, `done`, `n/a`, …). This returns wasted turns to actual detection on every scan — including black-box, where the agent's turn budget is the main constraint.

## [v4.6.50](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.50) — verify_xxe: a deterministic XML External Entity confirmer (2026-09-03)

### Added
- **`verify_xxe`, a one-call deterministic XXE confirmer — the sibling of `verify_sqli` / `verify_ssti`.** Given a URL or a ledger hypothesis id, it POSTs a benign baseline XML document and then an XXE payload (a `DOCTYPE` declaring an external `SYSTEM file://` entity referenced in the body), and confirms the vulnerability when the target file's contents appear in the probe response but not the baseline — a parser with external entities disabled echoes the literal entity, never the file. On success it records exploit-proven CWE-611 evidence in the scan ledger for the agent to report (it does not auto-report). Same safety envelope as the other injection verifiers: it scope-checks the internally resolved host and refuses the operator's own machine/local network, honors the scan's request-rate policy and cancellation, uses the scan session auth, does not follow redirects, and is disabled in passive mode. XXE previously lacked the fast confirmation path the other injection classes had, so the agent hand-crafted payloads and chased out-of-band callbacks until it ran out of budget; with `verify_xxe` a file-read XXE now confirms and reports an independently verified finding in one to two turns.

## [v4.6.49](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.49) — Benchmark: SSTI challenges are single-signal (no incidental XSS) (2026-09-03)

### Fixed
- **The `ssti` and `whitebox-ssti` benchmark challenges no longer expose an incidental reflected XSS.** `sstiRender` reflected the `name` parameter unescaped, so the app exhibited both template injection AND a browser-confirmable reflected XSS. Now that the agent reliably confirms XSS (v4.6.46), a real run reported the easier XSS (CWE-79) and never scored the intended `ssti` class. `sstiRender` now HTML-escapes the input before evaluating `{{ a * b }}` (braces, digits, spaces, and `*` are untouched by escaping, so the `{{7*7}} → 49` probe still confirms), so the only signal is template injection — one unambiguous vulnerability per challenge.

Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.48](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.48) — Reach for the deterministic verifiers on first signal (2026-09-03)

### Changed
- **The depth-first methodology now steers the agent to the fast deterministic verifiers the moment a class signal appears** — `verify_sqli` (single-quote provokes a DBMS error), `verify_ssti` (a `{{a*b}}` expression that evaluates to its product), `verify_xss` (a nonce that actually executes in the browser), `verify_oob` (a blind RCE/SQLi/SSRF/XXE callback) — instead of hand-crafting a long PoC or launching sqlmap first. Each is a one-to-two-turn confirmation that records exploit-proven, gate-passing evidence, so a confirmed finding is reported far sooner. It also reinforces reporting a strong in-band signal (a reflected `/etc/passwd`, a `uid=0(root)` command output, a raw DBMS error) directly rather than stalling on an out-of-band callback that may never arrive. Surfaced by running the benchmark against the real agent: a run had burned its entire budget on manual probes and sqlmap without ever confirming an obvious error-based SQLi; with the guidance the same challenge now confirms via `verify_sqli` and reports an independently `verified` finding.

## [v4.6.47](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.47) — Benchmark: agent-event diagnostics + single-signal error-SQLi challenge (2026-09-03)

### Changed
- **The operator benchmark runner (`cmd/xalgorix-bench`) now logs the agent's tool calls, verifier/report outcomes, errors, and finish reason** instead of silently discarding every agent event. A failing challenge is now diagnosable end to end — you can see whether the agent discovered the route, which verifier ran, what proof it pasted, and why the reporting gate accepted or rejected the finding.

### Fixed
- **The error-based SQLi benchmark challenge no longer reflects its `id` parameter unescaped.** That unescaped reflection was an accidental reflected-XSS red herring that pulled the scanner off the SQL injection the challenge is meant to measure (a real run spent its whole budget chasing the reflection and never confirmed the SQLi). The `id` is now HTML-escaped in both the normal and the SQL-error response paths, so the only signal is the SQL syntax error on quote injection — one unambiguous vulnerability per challenge.

Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.46](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.46) — Browser-backed XSS detection: use system Chrome, stop dropping confirmed XSS (2026-09-03)

### Fixed
- **The scanner now uses a system-installed Google Chrome (`/usr/bin/chrome`, `/opt/google/chrome/chrome`) instead of falling through to rod's bundled/downloaded Chromium.** On hosts whose only browser is Google Chrome, rod's `LookPath` and the previous well-known-path list both missed it, so the browser silently fell back to a ~170MB Chromium auto-download (which then fails offline) — breaking `verify_xss` and every browser-backed check. Those install locations are now probed explicitly before the auto-download fallback.
- **A genuinely browser-confirmed reflected XSS is no longer dropped by the reflection-only false-positive gate.** `verify_xss` records concrete browser-execution proof (a dialog/console/DOM signal carrying the injected nonce) in the scan ledger, but the model does not always paste that verdict into `exploitation_proof`, so the finding was gated as "reflection only." The report path now folds the ledger's authoritative `verify_xss` confirmation into the proof before the gate runs, so a confirmed XSS is judged on the real evidence. Verified end-to-end against the benchmark: the reflected-XSS challenge now detects, confirms, reports, and is independently `verified`.

## [v4.6.45](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.45) — Benchmark now covers CSRF (positive + negative) (2026-09-03)

### Added
- **The black-box benchmark now exercises CSRF detection, completing coverage of every class the finding classifier recognizes.** Adds a `csrf` positive challenge: a state-changing `POST /account/email` (change the account email) whose form carries no anti-CSRF token and whose handler requires none, so a request forged from any origin changes state. A matching `safe-account` negative control serves the same form with a per-session anti-CSRF token and refuses any POST whose token is missing or wrong (403), so reporting CSRF there is a false positive. Both advertise the change-email endpoint from a crawlable `/` index. The benchmark now runs 25 challenges (15 positive + 10 negative), and every classifier-supported class (xss, sqli, open_redirect, idor, ssrf, rce, lfi, ssti, xxe, csrf) has at least one challenge. Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.44](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.44) — Benchmark now covers XXE (positive + negative) (2026-09-03)

### Added
- **The black-box benchmark now exercises XXE detection — a class the finding classifier already recognized but no challenge tested.** Adds an `xxe` positive challenge: a `/import` endpoint that accepts a POSTed XML document and, when the document declares an external entity pointing at a local file (a `DOCTYPE` with a `SYSTEM` `file://` identifier), resolves it and reflects the file content in the import result (a simulated `/etc/passwd` read). A matching `safe-import` negative control exposes the same endpoint but with external-entity resolution disabled, so a `DOCTYPE` is ignored and no file content is ever returned — reporting XXE there is a false positive. Both advertise the XML import endpoint from a crawlable `/` index. The benchmark now covers XXE alongside the existing classes (23 challenges: 14 positive + 9 negative). Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.43](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.43) — Native Z.AI (Zhipu GLM) provider support (2026-09-03)

### Added
- **Native support for Z.AI (Zhipu GLM), including the GLM Coding Plan (#511).** Two catalog entries ship: `Z.AI (standard API)` (base `https://api.z.ai/api/paas/v4`) and `Z.AI Coding Plan` (base `https://api.z.ai/api/coding/paas/v4`), both offered in first-run setup and the Settings → LLM provider list and keyed by API key. `glm-*` model ids now route to Z.AI automatically, and a GLM id is accepted in either case — a `GLM-5.3` selection is sent as the canonical `glm-5.3` — so a newly released model id is not rejected as Z.AI's catalog evolves.

### Fixed
- **Z.AI chat requests no longer hit a malformed `/v4/v1/chat/completions` URL (which Z.AI rejects with `401 token expired or incorrect`).** The OpenAI-compatible URL builder now treats an explicit API-version segment already present in a provider's base (Z.AI's `/v4`, OpenAI's `/v1`, …) as authoritative and only inserts `/v1` when the base carries no version at all. The fix is applied uniformly across every endpoint builder — the legacy single-call resolver, the composite resolver, the multi-provider router, and model discovery — so `https://api.z.ai/api/coding/paas/v4` resolves to `…/v4/chat/completions`. Existing providers are unaffected (MiniMax and OpenAI still resolve to `…/v1/chat/completions`).

## [v4.6.42](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.42) — Complete precision coverage: a negative control for every black-box class (2026-09-02)

### Added
- **Every black-box class now has a matched positive + negative control, so precision is measured uniformly, not just for four classes.** v4.6.41 introduced negative controls for XSS, open redirect, SQLi, and SSRF; this adds the remaining four so a false positive is caught on any class: `safe-lfi` (rejects `..`/path separators — no path traversal), `safe-cmdi` (refuses shell metacharacters in `host` — no command injection), `safe-ssti` (renders `name` as literal HTML-escaped text, never evaluating it — a `{{7*7}}` probe stays literal), and `safe-idor` (enforces object ownership — every `/api/orders/<id>` returns 403 with no record). The benchmark now runs 21 challenges (13 positive + 8 negative), one negative control per black-box class, so a change's effect on the false-positive rate is visible across the whole class set. Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.41](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.41) — Black-box benchmark now measures precision (negative controls) (2026-09-02)

### Added
- **The benchmark now measures false-positive rate, not just recall, via negative-control challenges.** Every challenge so far was vulnerable, so the benchmark only rewarded finding bugs — a scanner that over-reports (the failure mode all the reporting gates and verifiers exist to prevent) would still score perfectly. A `Challenge` can now be flagged `Negative`: the app handles the same kind of input as a positive challenge but SECURELY, so the correct outcome is NO finding of that class, and scoring inverts (a negative control is "solved" only when the class is correctly NOT reported; reporting it is a false positive). Four negative controls ship: `safe-search` (reflects input but HTML-escapes it — no XSS), `safe-redirect` (only relative same-origin redirects — no open redirect), `safe-sqli` (parameterized; a bad id returns a generic 400 with no database error — no SQLi), and `safe-fetch` (an allowlist refuses internal/metadata hosts with 403 — no SSRF). The scorecard reports a `Precision: N/M negative controls clean, K false positive(s)` line and marks each false positive with the offending finding id, so a change's effect on precision is measured alongside recall. Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.40](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.40) — Black-box benchmark challenges are now crawler-discoverable (2026-09-02)

### Changed
- **The black-box benchmark challenges now expose their vulnerable endpoint (and parameter) from a realistic index, so the benchmark measures crawl-then-detect rather than parameter-name guessing.** Only the `idor` challenge previously linked its endpoint from a landing page; the other seven (`reflected-xss`, `open-redirect`, `error-sqli`, `ssrf`, `ssti`, `lfi`, `cmdi`) served their vulnerable behavior at a fixed path with nothing advertising the path or the parameter name — so a scan could fail purely because it never guessed `?q=`/`?url=`/`?file=`/etc., not because it couldn't detect the bug. Each now serves a realistic `/` index (a form and/or an example link, e.g. a search form for `reflected-xss`, a catalog of `/product?id=` links for `error-sqli`, a link-preview form for `ssrf`) that exposes the endpoint path and parameter the way a real app would, so the scanner's crawler discovers the attack surface and the benchmark isolates detection ability. The vulnerable behavior is unchanged and still served on the endpoint paths. Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.39](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.39) — Lock in the source scanner's multi-language route/sink detection (2026-09-02)

### Changed
- **Deterministic regression coverage now pins the source scanner's multi-language route and sink detection.** The whitebox source-to-runtime bridge advertises support for Flask/FastAPI, Django, Express/Koa/Fastify, Spring, Go routers, and Rails, but its route/sink regexes were only tested for Flask and Express — and the Express false-positive fixed in v4.6.28 showed these patterns can carry real bugs. This adds `TestRouteScanCrossLanguage` (Go `r.GET(...)` / `mux.HandleFunc(...)`, Spring `@GetMapping`/`@PostMapping`, Django `path`/`re_path`, Rails `get`/`post`) and `TestSinkScanCrossLanguage` (Java `Runtime.getRuntime().exec`/`ProcessBuilder`, Go `os/exec`, PHP `shell_exec` → all recognized as `rce` sinks), which confirm every advertised language's routes and command-exec sinks are detected and guard against pattern regressions. All patterns already worked — this is contention-independent evidence and a regression fence, not a behavior change. Test-only; the shipped binary is unchanged.

## [v4.6.38](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.38) — Cross-language whitebox benchmark challenge (Node/Express RCE) (2026-09-02)

### Added
- **A Node/Express whitebox benchmark challenge (`whitebox-node-rce`) validates the source-to-runtime bridge on a second source language.** The four existing whitebox challenges are all Python/Flask, so the bridge — source-sink discovery, route extraction, and route↔sink correlation — was only exercised for one language. This adds an equivalent command-injection challenge whose source is JavaScript: an `app.js` with an **UNLINKED** `app.get('/internal/ping')` Express route whose handler calls `child_process` `exec('ping -c1 ' + host)`. Solving it requires the bridge to work across languages: the code scanner must recognize the JS command-exec sink and the Express route declaration (`app.get(...)`, distinct from Flask's `@app.route` decorator), correlate the sink to that handler, probe the route live, and prove RCE via the injected command's output. The route is not linked from any page, so black-box crawling cannot reach it. Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.37](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.37) — Fourth whitebox benchmark challenge (LFI / path traversal) (2026-09-02)

### Added
- **A fourth whitebox benchmark challenge (`whitebox-lfi`) widens source-to-runtime validation to local file inclusion / path traversal.** With `whitebox-cmdi` (RCE), `whitebox-sqli`, and `whitebox-ssti` all solving within the standard benchmark deadline, this adds an equivalent LFI challenge so the source-to-runtime bridge is exercised across a fourth class. Its vulnerable log-viewer route (`/internal/logs`, which concatenates a user-supplied `file` parameter onto a base directory and `open()`s it) is **not linked from any page**, so black-box crawling cannot reach it and solving it requires the bridge: scan the source, discover the route and the co-located file-read sink (which the code scanner types as a `fileio` sink → LFI), attribute the sink to that handler, probe the route live, then prove the traversal with the classic `?file=../../../../etc/passwd` → `root:x:0:0:…` read. Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.36](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.36) — Benchmark classifier prefers the CWE over description keywords (2026-09-02)

### Fixed
- **The benchmark's finding classifier now trusts the CWE over description keywords, so a genuine SSTI finding is no longer scored as a miss.** A `whitebox-ssti` run confirmed the `verify_ssti` tool works end-to-end — the agent reported an exploit-proven `Server-Side Template Injection (SSTI) … CWE-1336` on the correct route — yet the scorecard marked the challenge `[FAIL]`. The cause was in the benchmark scorer, not the agent: `classifyFinding` matched title/description keywords **before** falling back to the CWE, and the broad `rce` keywords (`remote code execution`, `code execution`, `command injection`) precede `ssti` in the keyword list. Because a proper SSTI report describes the remote code execution it can be escalated to (exactly what the `verify_ssti` guidance recommends), the finding matched `rce` first and was classified as the wrong class, so it did not count as solving the SSTI challenge. `classifyFinding` now prefers the authoritative, structured CWE (`CWE-1336` → `ssti`) when it maps to a known class, and only falls back to title/description keywords for findings that carry no (or an unmapped) CWE. This makes the benchmark's per-class scoring accurate for classes whose impact overlaps another class's keywords (SSTI/XXE/SQLi that escalate to RCE). Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.35](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.35) — Deterministic server-side template injection confirmer (verify_ssti) (2026-09-02)

### Added
- **`verify_ssti` confirms server-side template injection in one call — the SSTI sibling of `verify_sqli`.** The `whitebox-ssti` benchmark (v4.6.34) surfaced a gap: the source-to-runtime bridge correctly seeded and correlated the template sink to its route, but the agent still reported nothing within budget because proving SSTI relied on the model hand-crafting a `{{7*7}}` payload, reading the response, and recognizing the evaluated product — the same expensive, unreliable path that error-based SQLi had before `verify_sqli`. The new tool takes a ledger `hypothesis_id` (a source-route/authenticated-endpoint hypothesis) or a `url`, plus the `parameter`, and issues a benign baseline plus template payloads with **randomized operands** — `{{a*b}}` (Jinja2/Twig/Nunjucks) and `${a*b}` (Freemarker/JSP-EL/Velocity). It confirms injection when the computed **product** appears in the probe response but **not** in the baseline: a reflected-but-not-evaluated app echoes the literal `{{a*b}}` (which contains `a` and `b`, never their product), so the product's appearance proves the engine evaluated the expression. Random operands make a coincidental match astronomically unlikely, and the baseline-absence check rejects pages that happen to contain the number for unrelated reasons. On success it records exploit-proven evidence in the shared ledger and tells the agent to report it as High CWE-1336 (and pivot toward RCE via the engine's gadget); it does not auto-report. It reuses the shared injection-probe helpers (host resolution, rate-gating, session-authenticated send) and the whitebox guidance now lists it alongside `verify_sqli`/`verify_xss`/`verify_oob`. Safety: it resolves the target host internally and always scope-checks it (refusing the operator's own machine/listener), does not follow redirects, honors the request-rate policy and cancellation, and is disabled in passive mode.

## [v4.6.34](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.34) — Third whitebox benchmark challenge (SSTI) (2026-09-02)

### Added
- **A third whitebox benchmark challenge (`whitebox-ssti`) widens source-to-runtime validation to server-side template injection.** With `whitebox-cmdi` (RCE) and `whitebox-sqli` now solving within the standard benchmark deadline, this adds an equivalent SSTI challenge so the source-to-runtime bridge is exercised across a third injection class. Its vulnerable preview route (`/internal/preview`, which renders a concatenated user parameter through `render_template_string`) is **not linked from any page**, so black-box crawling cannot reach it and solving it requires the bridge: scan the source, discover the route and the co-located template sink (which the code scanner types as a template sink → SSTI), attribute the sink to that handler, probe the route live, then prove the injection with the classic `{{7*7}}` → `49` evaluation. Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.33](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.33) — Whitebox guidance teaches the source-to-runtime bridge (2026-09-02)

### Changed
- **The whitebox methodology briefing now drives the agent through the source-to-runtime bridge instead of describing the old hand-crafted flow.** The bridge shipped over v4.6.23–v4.6.32 (`scan_source_sinks`, `scan_source_routes`, `probe_hypothesis`, auto-seeding at scan start, and the `verify_sqli`/`verify_xss`/`verify_oob` confirmers) was fully built, but the whitebox briefing the agent reads at scan start still described the pre-bridge methodology — `code_search` a sink, trace it by hand, then hand-craft an exploit — and never mentioned the auto-seeded ledger or the new tools. A benchmark diagnostic showed the cost: with the correlated source→route hypothesis already sitting in the ledger from iteration 1, the agent spent its early budget black-box crawling (chasing a reflected XSS) and only reached the seeded SQL-injection route late, missing an 8-minute deadline it clears comfortably when it works the seeded lead first. The live-target modes (whitebox, and provision-and-DAST) now tell the agent to WORK THE SEEDED LEDGER FIRST: `claim_next_hypothesis` the top correlated source→route lead, `probe_hypothesis` it to confirm it is live, then CONFIRM the class deterministically with `verify_sqli` (error-based SQLi), `verify_xss` (browser-executed XSS), or `verify_oob` (blind RCE/SQLi/SSRF/XXE) — widening to broad black-box crawling only after the seeded leads are worked. The source-review mode (no live target) is unchanged. The guidance text was also refactored behind a pure `whiteboxGuidanceText` helper so it is unit-tested directly.

## [v4.6.32](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.32) — Deterministic error-based SQL injection confirmer (verify_sqli) (2026-09-02)

### Added
- **`verify_sqli` confirms error-based SQL injection in one call — the SQLi counterpart of `verify_xss`.** The source-to-runtime bridge (`scan_source_sinks` → `scan_source_routes` → `probe_hypothesis`) gets the agent to a reachable route that a source SQLi sink flows into, but PROVING the injection still relied on the model hand-crafting a quote payload, reading the response, and recognizing a DBMS error — several turns of scarce budget for a class black-box scanners already miss most (the `whitebox-sqli` benchmark took ~12 min to land it manually, and missed at 8 min). The new tool takes a ledger `hypothesis_id` (a source-route/authenticated-endpoint hypothesis) or a `url`, plus the `parameter` to test, and issues three scope-gated requests: a benign baseline, a single-quote payload that breaks SQL syntax, and a doubled-quote payload that re-balances it. It confirms error-based SQLi when a DBMS error (`You have an error in your SQL syntax`, `ORA-#####`, `SQLSTATE`, `PG::…`, `SQLite`, `unclosed quotation mark`) appears on the broken request but **not** on the benign baseline — rejecting always-on error pages outright. When the balanced request recovers (no error) it reports the classic break/recover signature at high confidence; when it still errors (some apps/WAFs error on any quote) it confirms at lower confidence. On success it records exploit-proven evidence in the shared ledger and tells the agent to report it as High CWE-89; it does not auto-report. DBMS-error detection reuses the same signatures as the reporting impact-gate (shared `LooksLikeSQLError`), so the confirmer and the gate never drift. Safety: it resolves the target host internally and therefore always scope-checks it (refusing the operator's own machine/listener), uses the scan's session auth, does not follow redirects, honors the request-rate policy and cancellation, and is disabled in passive mode.

## [v4.6.31](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.31) — Error-based SQL injection recognized as valid High proof (2026-09-02)

### Fixed
- **A reflected DBMS error is now treated as valid proof of error-based SQL injection instead of being silently dropped.** The `whitebox-sqli` benchmark (v4.6.30) surfaced a false negative: an agent could inject a quote, get back a database error that proves the injection point (`You have an error in your SQL syntax`, `ORA-#####`, `SQLSTATE`, `PG::…SyntaxError`, `SQLite error`), and still never file the finding. Three things conspired against it. (1) The agent prompt contradicted itself — one rule accepted a DB error as SQLi proof while the evidence standard listed "an error string" as *not* an outcome and the depth-first checklist omitted DB errors entirely, so the agent judged its own proof insufficient. (2) The reporting `checkClaimConsistency` C:H gate rejected a High/`C:H` error-based finding because a lone DB error carries no data-obtained marker. (3) The DBMS-error signatures were absent from the concrete-impact indicators, so error-based SQLi was auto-downgraded and never tagged exploit-proven. All three are fixed: the prompt now names a provoked DBMS error as a concrete error-based SQLi outcome (CWE-89) to report as High without extracting data; the C:H gate is SQLi-aware (a SQLi finding whose proof carries a native SQLi/DBMS-error signal satisfies C:H); and the DBMS-error signatures are recognized as concrete impact so the finding is tagged exploit-proven and the verifier can auto-confirm. A proven injection point is reported as High even when the PoC only triggered a database error rather than dumping rows. The SQLi carve-out is scoped to SQLi findings, so other classes still require real data-obtained evidence for C:H.

## [v4.6.30](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.30) — Second whitebox benchmark challenge (SQLi) (2026-09-02)

### Added
- **Second whitebox benchmark challenge (`whitebox-sqli`) widens source-to-runtime validation to a second injection class.** The `whitebox-cmdi` challenge (v4.6.27) proved the source-to-runtime bridge end-to-end for command injection; this adds an equivalent SQL-injection challenge so the bridge is exercised across classes rather than one. Its vulnerable reporting route (`/internal/report`, which concatenates a user parameter straight into a raw `SELECT`) is **not linked from any page**, so — as with `whitebox-cmdi` — black-box crawling can't reach it and solving it requires the bridge: scan the source, discover the route and the co-located SQLi sink, attribute the sink to that handler, probe the route live, then prove the injection. Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.29](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.29) — Handler-span route↔sink correlation (2026-09-02)

### Changed
- **Source route↔sink correlation now attributes a sink to its enclosing handler, not the whole file.** When source auto-seeding types a route by a co-located dangerous sink, it previously matched *any* sink anywhere in the same file — so in a multi-route file every route was typed with the same (often unrelated) vuln class. The first whitebox benchmark run showed this: all three routes in the challenge's `app.py` were typed `rce` even though only `/internal/run-check` actually contains the `os.popen` sink. Correlation now uses the route's handler span — a sink at line L is attributed to the route whose declaration is the nearest one at or above L (bounded by the next route declaration below it) — so only the route that genuinely reaches a sink is class-typed and prioritized; the others seed as ordinary attack-surface (`idor`) leads. This keeps `probe_hypothesis` and exploitation focused on the route that actually reaches the dangerous code.

## [v4.6.28](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.28) — Route-discovery precision fix (2026-09-02)

### Fixed
- **Source route discovery no longer mistakes ordinary `.get()`/`.post()` calls for HTTP routes.** The Express/Koa route pattern matched `<anything>.get("…")`, so common non-router calls — `request.args.get('host')`, `dict.get('key')`, `session.get('token')` — were scooped up as bogus route hypotheses (the first whitebox benchmark run seeded 4 routes for a 3-route app; the extra one was a "route" named `host` harvested from `request.args.get('host')`). The receiver is now restricted to router-like names (`app`, `router`, `routes`, `route`, `api`, `srv`, `server`, `mux`, `koa`, `fastify`), so only real route declarations are seeded — keeping the ledger and `probe_hypothesis` focused on genuine attack surface. Gin/Echo routers, which use upper-case method calls (`r.GET(...)`), are matched by the separate Go-router pattern and are unaffected. Surfaced by the v4.6.27 whitebox benchmark.

## [v4.6.27](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.27) — Whitebox benchmark challenge for the source-to-runtime bridge (2026-09-02)

### Added
- **A whitebox benchmark challenge that measures the source-to-runtime bridge end-to-end.** The benchmark harness could only measure black-box detection; the whitebox capability shipped over the last four releases (`scan_source_sinks`, `scan_source_routes`, `probe_hypothesis`, and auto-seeding at scan start) had no benchmark to prove it works. A `Challenge` can now carry a `SourceFiles` source tree, which the harness materializes to a temp directory and hands to the scan as the target's source repo (the real runner wires it via `SetSourceRepo`). The new `whitebox-cmdi` challenge is a small app whose command-injectable route is **not linked from any page** — black-box crawling cannot reach it, so solving it (class RCE) genuinely requires the bridge: scan the source, discover the route and the `os.popen` sink in the same file, probe it live, then exploit it. This is operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.26](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.26) — Auto-seed the ledger from whitebox source at scan start (2026-09-02)

### Changed
- **Whitebox source now auto-seeds the ledger at scan start — the source-to-runtime bridge fires from iteration 1.** The three whitebox tools (`scan_source_sinks`, `scan_source_routes`, `probe_hypothesis`) only ran if the model chose to call them, so a scan with source attached could spend early iterations black-box-crawling before the code was ever examined. Now, as soon as the source is resolved, the scan sweeps it for dangerous sinks and HTTP routes and seeds the ledger with the resulting hypotheses — dangerous sinks (`file:line`), reachable routes (real HTTP paths), and the route↔sink correlations (a route whose handler file has a dangerous sink is seeded class-typed and higher-confidence) — exactly as an uploaded OpenAPI/HAR context already auto-seeds the surface. The specialists get concrete, source-derived leads to `probe_hypothesis` and exploit from the first iteration instead of rediscovering them. Deterministic, bounded (per-sweep caps), and idempotent (the ledger dedups), so it never floods or duplicates; a no-op when no source is configured.

## [v4.6.25](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.25) — Touch the live target from a seeded hypothesis (probe_hypothesis) (2026-09-02)

### Added
- **`probe_hypothesis` closes the source-to-runtime loop: it touches the live target from a seeded hypothesis.** `scan_source_sinks` finds the dangerous code and `scan_source_routes` gives it a reachable path, but until now nothing acted on that path — the model had to hand-craft every request. The new tool takes a ledger hypothesis that carries a real HTTP path (a `source-route` hypothesis, or an ingested/authenticated endpoint), resolves it against the scan target, issues **one** baseline request, and records the response as evidence — turning a guessed route into a confirmed lead. A live `2xx` raises confidence and moves the hypothesis to `testing`; `401/403` flags it as a prime `authz_matrix` target; a `404`/connection failure marks it `blocked` so the scheduler stops spending budget on routes that aren't deployed. It uses the scan's session auth automatically (so authenticated routes are probed authenticated) and does not follow redirects (a `3xx` to `/login` is itself a signal). Safety: because the tool resolves the target host internally (the agent-loop scope gate keys off tool arguments and can't see it), it always scope-checks the resolved host with the same operator-machine guard `authz_matrix` uses and refuses loopback/RFC1918/the dashboard listener; it reuses the existing scope-agnostic request path, honors the scan's request-rate policy and cancellation, and is disabled in passive mode. Source-location (`file:line`) endpoints from `scan_source_sinks` are skipped — they carry no HTTP path.

## [v4.6.24](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.24) — Give source-discovered sinks a reachable HTTP path (scan_source_routes) (2026-09-02)

### Added
- **`scan_source_routes` completes the source-to-runtime bridge: it gives source-discovered sinks a reachable HTTP path.** `scan_source_sinks` (v4.6.23) finds the dangerous code (a sink at `file:line`), but a `file:line` is not something the runtime tools can request. The new tool extracts HTTP route declarations from the attached source across the common frameworks (Flask/FastAPI, Django, Express, Spring, Go routers, Rails) and seeds each into the shared ledger as a hypothesis with a **real, reachable path** — including internal/admin routes a black-box crawler never reaches. It then correlates routes with sinks by handler-file co-location: a route whose file also contains a dangerous sink is seeded **class-typed** (by the worst sink class present) at higher confidence with a data-flow note linking the two, turning "there is an rce sink somewhere" into "`POST /admin/exec` reaches it — attack it." Uncorrelated routes seed as authz/attack-surface (`idor`) leads. Seeding is bounded (max 40 per sweep) and idempotent (dedup by vuln class + path), and the tool degrades to a black-box fallback when no source is configured. Specialists `claim_next_hypothesis` and request the route on the live target to prove the vuln.

## [v4.6.23](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.23) — Bridge whitebox source to runtime (scan_source_sinks) (2026-09-02)

### Added
- **`scan_source_sinks` bridges whitebox source to runtime exploitation.** Black-box recon finds routes; whitebox search finds the dangerous code behind them — but nothing connected the two automatically. The new tool sweeps the attached source tree for dangerous sinks (RCE/command injection, SQLi, SSRF, file I/O→LFI, template→SSTI, deserialization, open redirect) using the same curated patterns as `code_search`, then seeds each hit into the shared ledger as a source→sink hypothesis tagged with its `file:line` and a `source-sink:` data-flow note — the first automated populator of `Hypothesis.DataFlow`. Each sink class is mapped to its canonical vuln class (e.g. `cmdi`→`rce`, `fileio`→`lfi`, `template`→`ssti`); discovery-only classes (secrets, auth, crypto) are deliberately not seeded. Seeding is bounded (max 40 hypotheses per sweep) and idempotent (dedup by class + `file:line`, so re-running adds nothing), and when no source is configured the tool degrades to a black-box fallback message. Specialists can then `claim_next_hypothesis` and trace each sink back to a reachable route to prove it on the live target — the first step toward source-to-runtime exploitation.

## [v4.6.22](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.22) — Stop dropping browser-confirmed XSS as a false positive (2026-09-01)

### Fixed
- **The false-positive gate no longer rejects a browser-confirmed XSS as "reflection only."** When `verify_xss` proves execution in a real browser, it emits a machine-generated proof — `Browser-confirmed XSS: a dialog:alert dialog carrying the nonce "…" fired while loading …` — but that phrasing matched none of the gate's execution markers, while the reflected payload the agent includes (`<script>`, `onerror=`) tripped the reflection-only check, so a genuinely proven XSS was dropped (and had to be re-reported, sometimes landing as needs-manual-verification). The gate now recognizes the verifier's execution tokens (and dialog/console/DOM signal kinds), so a browser-confirmed XSS passes through to the independent verifier instead of being discarded. Surfaced by the first benchmark baseline run.

## [v4.6.21](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.21) — Benchmark scoring, robustness, and a per-challenge timeout (2026-09-01)

### Changed
- **Benchmark scoring is now class-based.** Each challenge app hosts exactly one vulnerability, so a finding of the expected class against it counts as solved; the previous exact-endpoint requirement wrongly failed a correct detection when the agent proved the bug on a different path (e.g. reflected XSS confirmed at `/?q=` rather than a declared `/search`). Path precision is a separate concern from class detection, which is what the benchmark measures.
- **Per-challenge wall-clock timeout.** `bench.RunWithTimeout` (and a `-timeout` flag on `xalgorix-bench`, default 8m) bound each challenge scan and mark timeouts on the scorecard, so a wandering or stuck scan can no longer hang the whole run; partial findings gathered before the deadline are still scored.

### Fixed
- **IDOR challenge no longer panics on non-`/api/orders/` paths** (it sliced the prefix off every request path) and now serves a small index linking to a concrete object so the endpoint is discoverable by the crawler.

## [v4.6.20](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.20) — More benchmark challenges (SSRF, SSTI, LFI, command injection) (2026-09-01)

### Added
- **Four more benchmark challenge classes.** The benchmark harness now covers SSRF (an internal-target fetch returns cloud-metadata-like secrets), SSTI (a `{{7*7}}` expression evaluates to `49`), LFI/path traversal (`../../etc/passwd` returns passwd-like content), and command injection (a shell metacharacter yields `uid=0(root)`), on top of the existing reflected XSS, IDOR, open redirect, and error-based SQLi. Each challenge simulates the dangerous outcome rather than performing a real fetch/exec/file-read, so the set stays hermetic and safe while presenting a crisp, detectable signal. All four map to existing scoring classes, so `xalgorix-bench` now measures eight classes.

## [v4.6.19](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.19) — Benchmark harness (measure detection per class) (2026-09-01)

### Added
- **A benchmark harness to measure detection, per vulnerability class.** New `internal/bench` package hosts a set of deliberately vulnerable, self-contained challenge apps (reflected XSS, IDOR, open redirect, error-based SQLi to start) and deterministically scores a scan's findings against the expected class and endpoint — so the effect of a change on real detection can be measured instead of assumed. The heavy agent run is injected as a `ScanFunc`, keeping the challenge apps, scoring, and aggregation fully unit-tested without any model calls. A new operator command, `xalgorix-bench`, wires the real agent and prints a per-class scorecard; it needs `XALGORIX_LLM`/`XALGORIX_API_KEY` and makes live calls, so it is a local tool and not part of the shipped release. This is the first step toward the repeatable evaluation the roadmap requires before any parity claim; the challenge set is intentionally small and will grow.

## [v4.6.18](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.18) — CWE-aware duplicate detection (2026-09-01)

### Changed
- **Duplicate detection now falls back to the CWE when a finding's title doesn't name its class.** The near-duplicate check keys on vulnerability class, which it inferred from title/description keywords — so a finding worded without the class name (e.g. "Unauthenticated contact creation" that is really stored XSS, tagged CWE-79) escaped class-based dedup and paid for its own full verification. When no keyword is present, the finding's CWE is now mapped to the class, so same-class findings on the same endpoint collapse as intended. The mapping is limited to high-confidence, common CWEs; an unmapped CWE with no keyword still yields no class, so the fallback never over-merges distinct findings.

## [v4.6.17](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.17) — Deterministic claiming of the next hypothesis (2026-09-01)

### Added
- **`claim_next_hypothesis` turns the evidence ledger into a real work queue.** The shared ledger already ranked untested hypotheses by confidence, but picking and assigning one was left to free-form model choice — so an agent could skip the strongest lead, and two parallel specialists could grab the same target. The new tool atomically claims the highest-confidence *queued* hypothesis (optionally scoped to a `vuln_class` lane), assigns it to the calling agent, and moves it to `testing` in one locked step — then hands back its next action and baseline. Specialists are now directed to claim their lane with it instead of eyeballing the ledger, so scheduling is deterministic and collision-free, and the coordinator provably works the most promising leads first.

## [v4.6.16](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.16) — Precision: dedup object-ID variants before verification (2026-09-01)

### Changed
- **Findings that are the same bug across different object IDs are now recognized as one.** Duplicate detection compared endpoints literally, so `/orders/1042`, `/orders/2087`, and `/orders/<uuid>` looked like three distinct findings — each one paying for a full independent verification pass and landing as a separate report. Deduplication now templates opaque per-object id segments (pure numbers, UUIDs, long hex/ObjectIds) to a placeholder when comparing endpoints, so object-id variants of the same endpoint collapse into a single finding. The templating is conservative (version segments like `v1`/`v2` and named paths are never collapsed) and applies only to the duplicate-comparison key — the stored and reported endpoint keeps the real id so the PoC stays reproducible. Because every dedup path (report gates and child→parent merge) shares this logic, it also cuts redundant, expensive verifier runs — precision over volume.

## [v4.6.15](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.15) — Two-account IDOR/BOLA from a second ingested session (2026-09-01)

### Added
- **`ingest_har` can now register a SECOND account (`role=b`) for true two-account IDOR/BOLA.** Proving broken object-level authorization needs two real identities: one user's session reaching another user's objects. Capture a HAR while logged in as a second user and run `ingest_har path=… role=b` — its session is registered as role B (a dedicated store that is deliberately *not* auto-applied to `http_request`, since role B is the "other user" identity used on purpose). `authz_matrix` then uses that ingested session as role B (when no operator second account is configured, mirroring how role A already falls back to an ingested session), replaying each request as role A, role B, and anonymous to flag any of role A's resources that role B can reach. Role-B ingestion registers credentials only — it does not seed the ledger, since role B is a comparison identity, not new attack surface.

## [v4.6.14](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.14) — Uploaded context seeds the hypothesis ledger (2026-09-01)

### Changed
- **Uploaded scan-context artifacts now seed the hypothesis ledger, not just a briefing.** When a scan starts with an OpenAPI/Swagger spec, HAR, Postman collection, or Burp export, Xalgorix already parsed it into a normalized endpoint surface and registered any captured session — but the endpoints only appeared as a passive text briefing. They now also become bounded, role-scoped authorization hypotheses (the prime IDOR/BOLA surface) in the shared ledger, so the operator-supplied surface directly drives `authz_matrix` and the evidence-driven specialists instead of relying on the model to re-derive targets from prose. Role is `authenticated` when the artifact carried a live session, otherwise `anonymous`. Seeding is deduplicated (by class/endpoint/parameter/role) and bounded, so it never floods the scheduler or double-counts across sub-agents. This mirrors what `ingest_har` does mid-scan, now applied to every context upload at scan start.

## [v4.6.13](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.13) — Ingested session drives the authorization matrix (2026-09-01)

### Changed
- **An ingested authenticated session now powers `authz_matrix` directly.** When a scan's credentials come from a logged-in HAR (`ingest_har`) rather than a separately configured operator account, `authz_matrix` now adopts that session as role A. Previously the HAR seeded IDOR/BOLA hypotheses but the matrix meant to test them saw only anonymous access and refused to run — so the authenticated surface never got exercised. Role A is the operator account when one is configured (unchanged, deterministic precedence) and otherwise the ingested session, closing the loop from `ingest_har` → session auth → cross-identity access-control testing.

## [v4.6.12](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.12) — Authenticated-context ingestion from HAR (2026-09-01)

### Added
- **`ingest_har` starts a scan from a real logged-in session.** Point it at a HAR captured while authenticated and it (1) registers the session credentials it carries (Authorization / Cookie / API-key headers) so subsequent `http_request` and `authz_matrix` calls are authenticated, and (2) seeds the ledger with the HAR's authenticated endpoints — the prime IDOR/BOLA surface — as role-scoped (`role=authenticated`) authorization hypotheses for the specialist to work. A new `internal/har` parser extracts the exercised endpoints (static assets skipped), their query/body parameters, and the session headers, with host-scope filtering. This gives Xalgorix the authenticated business-logic surface that unauthenticated crawling never reaches.

## [v4.6.11](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.11) — Auto-link reported findings to their ledger hypothesis (2026-09-01)

### Added
- **`report_vulnerability` accepts an optional `hypothesis_id`.** When the agent reports a finding that proves a ledger hypothesis (its id comes straight from `authz_matrix` / `verify_xss` / `verify_oob` / `record_hypothesis`), the finding is linked to that hypothesis and the hypothesis is marked proven on a successful report — closing the loop the precision finish-gate enforces without a separate `add_hypothesis_evidence` call. The link is deterministic (the agent names the exact id, no fuzzy matching) and best-effort: an empty or unknown id is a silent no-op, so it can never fail a valid report.

## [v4.6.10](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.10) — Out-of-band blind-vulnerability verification (2026-09-01)

### Added
- **`verify_oob` confirms blind vulnerabilities via the OAST oracle and records them in the ledger.** After minting a callback with `oob_callback` and planting it in a target-side payload, `verify_oob` polls the token and applies a class-aware verdict: SSRF requires an assessed non-scanner HTTP interaction, while blind RCE / command injection / XXE / SQL injection are confirmed by any genuine non-scanner callback (HTTP or a DNS lookup of the unique token). Confirmed results are recorded as role-scoped ledger evidence, giving Xalgorix a deterministic proof path for the classes that leave no in-band signal — directly targeting the blind-injection gap where autonomous scanners are weakest.

## [v4.6.9](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.9) — Broader XSS execution verification (console + DOM oracles) (2026-09-01)

### Added
- **`verify_xss` now confirms execution via console calls and DOM markers, not just dialogs.** The headless browser captures `console.*` API output as execution signals, and the verifier also reads DOM markers (`document.title` / `window.name`) after navigation. A payload can therefore prove execution by firing a dialog, by logging the nonce to the console (useful when a filter strips `alert()`), or by mutating a DOM marker to the nonce — extending confirmed XSS coverage to non-dialog and DOM-only sinks while keeping the same "proof of execution, not reflection" bar.

## [v4.6.8](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.8) — Evidence-driven multi-agent assessments (2026-09-01)

Scan-scoped parallel specialists coordinated by a durable hypothesis/evidence ledger, plus deep-testing tools for the vulnerability classes autonomous scanners are weakest at (broken authorization, XSS).

### Added
- **Scan-scoped multi-agent assessments.** Coordinator-led parallel specialists are enabled by default: full assessments split mature reconnaissance into two or three non-overlapping, hypothesis-driven roles (authorization/business logic, injection/server-side behavior, and source/data-flow or client/API analysis). `spawn_agent`, `check_agent`, and `wait_agent` are always available, and the root finish gate requires every running or completed delegation to be collected before the scan can finish.
- **Durable, scan-shared hypothesis/evidence ledger.** A new typed ledger on the scan context records every attack hypothesis (vulnerability class, endpoint, parameter, role/data-flow, preconditions, baseline, confidence, status, and next action) with append-only evidence. It is deduplicated, memory-bounded, and persisted atomically to `ledger.json`, so the coordinator and every specialist read and write one shared graph that survives restart/resume. New agent tools `record_hypothesis`, `add_hypothesis_evidence`, `update_hypothesis`, and `read_ledger` operate on it.
- **The ledger drives scheduling.** Once reconnaissance produces a plan, the ledger is seeded with a hypothesis per candidate class. Delegation is ledger-driven: the coordinator assigns disjoint, contract-bound work to deterministic specialist profiles — authorization/business-logic, injection/server-side, and client/source — each carrying an explicit evidence contract (baseline + concrete proof; out-of-band callbacks for blind classes; browser-confirmed execution for XSS/DOM) and a stopping rule.
- **Multi-role authorization matrix (`authz_matrix`).** Replays a single request as every configured identity — the primary session (role A), a second account (role B) when the scan has one, and anonymous — and reports the access-control differential. When a lower-privileged identity receives the same successful response as the authorized one, that is broken access control (IDOR/BOLA for a second user, auth bypass/BFLA for anonymous). It enforces scope (never probes the operator's own machine) and the per-scan request-rate policy, and records role-scoped hypotheses with the differential as evidence.
- **Browser-backed XSS execution verification (`browser_action command=verify_xss`).** The headless browser now records JavaScript dialogs as execution signals; the new action navigates a payload that raises a dialog carrying a unique nonce and confirms XSS only when that dialog actually fires — proof of execution rather than mere reflection. Confirmed results are recorded as browser-confirmed XSS evidence in the ledger.
- Injection/server-side and client/source specialist profiles now point at `authz_matrix` and `verify_xss` in their evidence contracts, so specialists produce the required proof automatically.

### Fixed
- **A scan could finish with proven work unreported.** A precision finish-gate now blocks completion while any hypothesis is marked proven but has no linked finding, requiring the agent to file it (and link the finding) or downgrade it. The gate is bounded so it can never deadlock a scan, and it complements the existing coverage gate rather than replacing it.
- **Concurrent scans could cross-wire sub-agents.** The delegation runner, agent map, concurrency semaphore, stop flag, and cleanup path were process-global. Constructing another root or child overwrote the runner; cleanup could clear another live scan; streamed partial results used the internal agent ID instead of the coordinator-visible delegation ID; and reset did not cancel a child already inside `Run`. Each root now owns a cancellable `agentsgraph.Graph`, descendants share only that graph, worker slots are per scan, partial/final evidence uses one stable ID, and shutdown waits briefly for children before persisting and deleting scan stores.
- **Parallel reports could borrow the wrong Verifier LLM client.** Verifiers were selected through one mutable callback per scan context, so a newly constructed child could replace the callback used by its siblings. `report_vulnerability` now captures the reporting agent's independent verifier in its own tool registry; parallel hunters block on their own verifier client and cannot overwrite or race a sibling's validation loop.
- **Delegated agents multiplied per-scan resource caps.** Each child previously received fresh duration, iteration, token, and tool-call counters, so a coordinator plus three specialists could consume roughly four times the configured caps. The graph now shares one scan budget: the root starts the wall clock once, agent iterations and tool-call batches atomically reserve the remaining allowance, and token deltas aggregate across agent clients.

## [v4.6.7](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.7) — Manual instance capacity (2026-09-01)

### Fixed
- **Explicit instance capacity was still reduced by adaptive RAM admission.** When `XALGORIX_MAX_INSTANCES` is set, it now defines the authoritative number of concurrent scan instances instead of acting only as an upper bound on a smaller RAM-derived estimate. Adaptive RAM admission remains the default when the variable is unset, heavy tools remain resource-throttled, and the critical disk floor still blocks new work.

## [v4.6.6](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.6) — Concurrent admission and restart recovery (2026-09-01)

### Fixed
- **Healthy scans could remain pending even above the configured instance cap.** The RAM admission model calculated how many *additional* scans fit in currently available memory, but compared that number as though it were the total concurrency ceiling. As running scans consumed RAM, the UI could report an impossible state such as six running with `Max 5`, and new work stayed pending despite `XALGORIX_MAX_INSTANCES=20`. Admission and resource telemetry now add the already-running instances back to remaining RAM headroom, while still enforcing the manual cap and critical RAM/disk safety floors. Newly admitted scans temporarily reserve their estimated slot until their allocations are reflected in host telemetry, so a burst of pending jobs cannot all spend the same RAM snapshot. The Instances resource card now shows total capacity, running instances, and available slots separately.

## [v4.6.5](https://github.com/xalgord/xalgorix/releases/tag/v4.6.5) — Opt-in scan-completion notifications (2026-08-30)

### Added
- **Completion-summary control for Discord and Telegram.** `XALGORIX_NOTIFY_SCAN_COMPLETE` lets operators opt in to queue-level and report-level scan-completion summaries. It defaults to `false`; per-vulnerability alerts are unchanged.

### Fixed
- **Race-safe live notification updates.** Runtime setting changes are synchronized, and regression coverage verifies both enabled and disabled delivery paths.

### Documentation
- Documented the new setting in the README and architecture guide and regenerated the embedded Web UI assets.

## [v4.6.4](https://github.com/xalgord/xalgorix/releases/tag/v4.6.4) — macOS ARM64 and multi-architecture images (2026-08-29)

### Added
- Added native macOS ARM64 release support and multi-architecture container images.

## [v4.6.3](https://github.com/xalgord/xalgorix/releases/tag/v4.6.3) — Token usage and hosted-cost guidance (2026-08-27)

### Added
- The CLI now reports LLM token usage when a scan ends and explains which model costs are covered by the hosted service.

### Documentation
- Added a direct comparison of self-hosted and hosted Xalgorix, including operational responsibilities and cost tradeoffs.

## [v4.6.2](https://github.com/xalgord/xalgorix/releases/tag/v4.6.2) — MiniMax native web search (2026-08-26)

### Added
- MiniMax-backed scans now use MiniMax's native `web_search` capability.

## [v4.6.1](https://github.com/xalgord/xalgorix/releases/tag/v4.6.1) — Evidence integrity hardening (2026-08-24)

### Fixed
- Reporting rejects fabricated or unreachable non-findings and no longer treats a description as proof of exploitation.

## [v4.6.0](https://github.com/xalgord/xalgorix/releases/tag/v4.6.0) — Brand refresh and UX milestone (2026-08-23)

### Added
- Replaced the legacy opaque mark with a transparent vector logo and regenerated the favicon, dashboard, login, and README assets.
- Added persisted Light, Dark, and System dashboard themes with no-flash startup behavior.
- Added multi-file Postman uploads so a collection and environment can be supplied together, with variables and authentication resolved into the seeded attack surface.

### Compatibility
- No breaking changes; existing installations can upgrade in place.

## [Unreleased] — Provider model selector

### Added
- **Provider model selection across authentication methods.** Settings now renders one reusable model field for API-key, OAuth, and credential-free providers. Saved values retain the canonical `provider/model` routing prefix.
- **Live provider model discovery.** Providers with compatible OpenAI, Anthropic, Gemini, or Ollama model-list endpoints automatically load the models available to the selected credential. Discovery runs server-side and keeps credentials out of the browser. The built-in catalog no longer hardcodes model examples; providers without discovery support use explicit manual entry.
- **Novita AI provider.** The built-in catalog now includes Novita's OpenAI-compatible API endpoint and API-key authentication, with models loaded dynamically from Novita's API.

## [Unreleased] — Provider-specific CLI credential errors

### Fixed
- **Codex sign-in incorrectly reported missing Claude credentials.** Both CLI-reuse drivers previously returned the Claude-specific `auth.ErrNotFound` sentinel, so OAuth completion responded with `claude cli credentials not found` when the Codex credential was unavailable. Codex now returns a dedicated sentinel and the API responds with `codex cli credentials not found`. The sign-in modal also identifies the expected Codex credential path and read-only Docker mount.

## [Unreleased] — Per-scan live guidance

### Added
- **Operators can guide an agent while its scan is running.** The individual scan Events tab now includes a per-instance message composer with focused guidance suggestions, keyboard submission, delivery feedback, and responsive layout. Messages are routed to the exact running `instance_id`, queued for the agent's next iteration without interrupting its active work, and then surface in the same instance event stream. The WebUI client response type now also matches the existing `/api/chat` response contract.

## [Unreleased] — Markdown rendering in finding details

### Fixed
- **Finding text rendered raw Markdown in the dashboard.** The finding detail dialog showed `description`, `impact`, `technical_analysis`, and `remediation` as plain text, so the LLM-emitted Markdown (`##` headings, `**bold**`, fenced code, lists) appeared as literal characters. Added a small dependency-free Markdown renderer (`webui/src/components/markdown.tsx`) and use it for all non-code sections; the full description now renders as its own section. Code fields (PoC script, exploitation proof, suggested fix) stay verbatim in `<pre>`.

## [Unreleased] — Recognize command-injection RCE as proven

### Fixed
- **Genuine OS command-injection RCE was flagged "manual verification needed"** despite proof of root command execution. A critical `/uptime/{flag}` finding (CVSS 9+) whose proof showed `whoami`→`root`, `uname -a`→`… x86_64 GNU/Linux`, `uptime`→`load average …`, and full source-code disclosure was tagged `needs-manual-verification`. Cause: the concrete-impact detector (`HasConcreteImpact` and the reproduced-/concrete-impact indicator lists) only recognized command execution via `id`/`cat /etc/passwd`-style output (`uid=`, `gid=`, `root:`, `/etc/passwd`); it did not recognize `whoami`, `uname`, `uptime`, or Windows command output, so neither the independent Verifier's auto-confirm nor the `exploit-proven` classification fired. Added high-signal command-execution markers (`gnu/linux`, `load average`, `nt authority\`, `volume serial number`, `windows ip configuration`, `microsoft windows [version`) to both lists. Such findings are now `verified`/`exploit-proven` (Verified=true) instead of flagged for manual review. Regression: `TestHasConcreteImpact_RecognizesCommandExecutionOutput`.

## [Unreleased] — Phase-progress accuracy

### Fixed
- **Phase progress jumped to a late phase during reconnaissance** (e.g. showed "8. IDOR / BAC" at iteration 4 while still fingerprinting). `inferCurrentPhase` mapped ubiquitous HTTP tokens in tool arguments to methodology phases — `authorization` → 8, `cookie` → 4, `login`/`session` → 5, `/api/`/`graphql` → 9 — but those appear in ordinary requests on nearly every target (an authenticated scan sends an `Authorization` header from its first recon request), so the bar false-jumped immediately. Those keyword heuristics are removed; phases without a dedicated tool signal now advance only via the agent's explicit phase narration. Additionally, the reported phase is now **monotonic** (progress only moves forward) so it no longer bounces backward when the autonomous agent revisits recon between exploit attempts. Regression guard in `TestInferCurrentPhase_*`.

## [Unreleased] — "Exploit-proven" verification state

### Fixed
- **Proven findings were being flagged "manual verification needed."** When the independent Verifier returned an *inconclusive* verdict (ran out of turn/time budget, hit an LLM error, or the class needs state/timing/OOB it lacks), the finding was tagged `needs-manual-verification` regardless of the strength of its own proof — so a proven RCE whose exploitation proof shows `uid=0(root)`, or a SQLi that dumped rows, was presented as unverified. The verification dimension now has three states: `verified` (independently reproduced by the Verifier), **`exploit-proven`** (Verifier inconclusive/absent, but the finding's OWN proof contains a concrete exploitation outcome per `HasConcreteImpact` — command output, extracted data, OOB callback, SQL extraction, cloud-metadata), and `needs-manual-verification` (no concrete proof yet). `Verified` is now true for both `verified` and `exploit-proven`, so reports no longer stamp proven findings "UNVERIFIED — manual review required." Regression: `TestReportVuln_IndependentVerifierGate/inconclusive_with_concrete_first-party_proof_is_EXPLOIT-PROVEN`.

## [Unreleased] — Internal refactor: decompose web/agent god-files

### Changed
- **Behavior-preserving decomposition of the two largest files** into cohesive, single-purpose files within their existing packages. No logic changed (verified: top-level declaration sets identical vs the prior revision, and code content byte-identical except two removed stale orphan comments; build/vet/gofmt/golangci-lint clean, tests + `-race` green).
  - `internal/web/server.go` 8865 → 3187 LOC, split into `auth_session`, `ws_hub`, `queue_state`, `orchestrator`, `uploads`, `notify`, `scan_session`, `chat`, `schedules`, `scan_list`, `scan_query`, `scan_record`, `legacy_import`.
  - `internal/agent/agent.go` 4028 → 1422 LOC, split into `agent_prompt`, `agent_ratepolicy`, `agent_messages`, `agent_guard`.

## [Unreleased] — Report accuracy vs severity filter (customer feedback)

### Fixed
- **Report omitted findings the live severity filter hid.** When a scan was launched with a `severity_filter` (e.g. only show `critical` live), a vulnerability below that threshold was dropped from `sess.record.Vulns` entirely — so it never reached the on-disk `scan.json` or the PDF report. Customers saw "report shows no findings, but the logs show findings, even critical." The severity filter is now a **display/broadcast gate only**: every vuln the agent reports is always persisted to the scan record (and thus the report + `/api/findings`), and the filter only suppresses the real-time WebSocket broadcast and Discord/Telegram notification. `report_vulnerability` event handling in `internal/web/server.go` no longer wraps persistence in the `if allowed` block. Regression tests: `TestReportPersistsBelowFilterVulns`, `TestAppendVulnSummaryUniqueIsFilterAgnostic`.

## [Unreleased] — Telegram bot notifications (#157)

### Added
- **Telegram bot notifications** as a first-class notification channel alongside Discord. Operators configure a bot token + chat ID (`XALGORIX_TELEGRAM_BOT_TOKEN`, `XALGORIX_TELEGRAM_CHAT_ID`, `XALGORIX_TELEGRAM_MIN_SEVERITY`) and receive the same lifecycle and finding notifications Discord already receives: scan started, vulnerability found (severity-gated), scan finished, the completed PDF report delivered via `sendDocument`, and service restart/stop events. Telegram and Discord are independent and can be enabled together or separately.
  - New `sendTelegram` / `sendTelegramWithFile` helpers in `internal/web/server.go` mirror `sendDiscord` / `sendDiscordWithFile` (fire-and-forget goroutine, 30s timeout, `safe.Recover` boundary, early-return when unconfigured). Text messages use HTML parse_mode; the PDF report is attached as a `sendDocument` multipart upload. Telegram logical `ok:false` responses (HTTP 200 with an error body) are logged without crashing the scan.
  - The outbound host is pinned to `api.telegram.org` over HTTPS (not operator-configurable) so an attacker-influenced base URL cannot create an SSRF surface.
  - The bot token is `Sensitive: true` in the settings registry and never returned by any `/api/...` response; only a `telegram_configured` boolean is surfaced on scan records (mirrors the existing `discord_webhook_configured` redaction pattern verified in `server_test.go`).
  - Settings → Notifications tab now has a Telegram card (bot token, chat ID, minimum severity) and the Integrations page has a Telegram bot card.
  - v1 is global-only (no per-scan Telegram override); per-scan parity with Discord is tracked as a future follow-up.

## [Unreleased] — Loop-breaker for repeated identical tool calls

### Fixed
- **Endless loop on repeated identical tool calls (#158).** The agent could spin indefinitely, regenerating the same tool call (most commonly `terminal_execute`) with identical arguments and an identical failing result — observed reaching iteration 2106+ with no progress. Stuck detection in `internal/agent/hooks.go` only accumulated for `browser_action` and `web_search`; the default branch of `hookStuckTracker` reset all stuck counters for every other tool, so a loop on `terminal_execute` (or any non-browser/search tool) never tripped a nudge or force-skip and ran until `MaxIterations` (default 0 = unlimited) or process kill.
  - New `ScanState` fields track consecutive identical `(tool, args)` and consecutive byte-identical tool outputs; these counters are deliberately NOT reset by `OnHealthyResponse` (a "healthy" response re-issuing the same call is exactly the loop).
  - New thresholds `RepeatCallSoftNudge=3`, `RepeatCallHardSkip=5`, `RepeatResultHardSkip=4`.
  - `hashToolArgs()` (order-independent FNV-64a) and `resultFingerprint()` detect identical `(tool, args)` and identical output across iterations.
  - `hookStuckTracker`'s default branch now counts consecutive identical calls; `add_note`/`read_notes` are excluded so legitimate note-taking between identical test calls doesn't reset the counter.
  - New `hookResultRepeatTracker` on `OnToolResult` counts byte-identical outputs (ignores `add_note`/`read_notes`/`finish`).
  - `hookStuckNudge` force-skips + nudges ahead of the browser hard-limit on repeated identical call (soft/hard) and repeated identical output; counters reset after firing.

### Notes
- No change to `agent.go` (existing `ForceSkip`→skip / `Nudge`→user-message machinery already consumes the result) and no change to the `MaxIterations` default (legitimate wildcard scans run thousands of iterations).
- Known follow-up, not fixed here: the three block branches in `agent.go` (`shouldBlockForActivityPolicy` / `shouldBlockForPhaseRestriction` / `shouldBlockForOutOfScope`, ~L1547-1581) still do not increment any stuck counter.

## [Unreleased]

### Added
- **`POST /api/restart`** — schedules a graceful backend restart from the dashboard/API. The restart never interrupts active work: it waits until the scanner is idle (no running/pending/paused/queued/starting instances, no in-progress scan, no leased tool processes) before restarting, then in-flight scans auto-resume. Shares the same `scannerIdle` gate and restart-when-idle watcher as the existing `xalgorix --restart-when-idle` (SIGUSR1) path. Returns `{ "status": "scheduled"|"already_pending", "idle": <bool> }`. Inherits the existing auth + CSRF stack as a mutating route.

## [Unreleased] — Runtime-editable provider catalog and OAuth flows

### Added
- **Runtime-editable provider catalog** at `~/.xalgorix/data/providers.json`. The file ships empty: there are no baked-in defaults, no startup writes, and no auto-fetch. Operators populate it through the dashboard or the new HTTP API. Catalog reads/writes use atomic temp-rename with `0600` file mode and a parent dir `chmod 0700`; corrupt JSON is treated as empty for `List` and refuses every `Create`/`Update`/`Delete` until the file is fixed.
- **Four OAuth flows** for storing per-provider credentials, all coalesced through a single `Driver` registry and a `TokenSink` that serializes refreshes per `(provider, profileId)`:
  - `pkce`: loopback redirect on `127.0.0.1:<ephemeral>` with PKCE S256 plus a paste-fallback that activates automatically when `XALGORIX_BIND` resolves to a non-loopback address.
  - `device_code` (RFC 8628): polls the token endpoint at the server-supplied interval, honors `slow_down`, and surfaces `408` on `expires_in` timeout.
  - `setup_token`: posts an operator-supplied bearer to the configured `tokenEndpoint` and persists the resulting profile.
  - `claude_cli_reuse`: read-only import of the Claude CLI credential file; mtime + SHA-256 of the source file are unchanged after import.
- **Operator-triggered openclaw catalog import** via `POST /api/providers/import-openclaw`. HTTPS-only, skip-on-collision merge with a per-entry `outcomes` envelope. Upstream non-2xx responses bubble up as a `502` envelope and the on-disk catalog is left untouched.
- **Per-scan `provider_profile` field** on `ScanRequest`. The web layer's `resolveScanCredentials` resolves the routing precedence `provider_profile → catalog default → legacy env`, with explicit `api_key` overrides forcing API-key auth. Unknown profile keys fail fast with `400` before any scan goroutine spawns.
- **One-time legacy migration banner.** When `XALGORIX_LLM` (or `XALGORIX_API_KEY`) is set and both `providers.json` / `auth-profiles.json` are absent or empty, the dashboard offers a one-click migration that materializes a `legacy` catalog entry plus a `legacy:default` API-key profile and drops a `.legacy-providers-migrated` sentinel. The importer never modifies `~/.xalgorix.env`.
- **New HTTP routes** under the existing auth + CSRF stack:
  - `GET/POST /api/providers`, `PUT/DELETE /api/providers/{id}`, `POST /api/providers/import-openclaw`
  - `GET/POST /api/providers/migrate-legacy` and `GET /api/providers/migrate-legacy/status`
  - `GET /api/auth/profiles`, `POST /api/auth/profiles/api-key`, `POST /api/auth/profiles/oauth/start`, `POST /api/auth/profiles/oauth/complete`, `POST /api/auth/profiles/{key}/refresh`, `DELETE /api/auth/profiles/{key}`
  All credential strings (`apiKey`, `accessToken`, `refreshToken`) are masked via `maskAuthCredential` on every response while metadata (`expiresAt`, `scopes`, `tokenType`, `requiresReauth`, `apiBaseOverride`) round-trips unmasked.
- **Settings → Providers tab** in the dashboard composing the catalog editor, profile list with per-flow OAuth modal (loopback / device / paste shapes), openclaw import button, and the legacy migration banner.

### Changed
- The LLM client now resolves outbound endpoints through a composite resolver: when the catalog is non-empty it routes through `catalogResolver`; when the catalog is empty and `XALGORIX_LLM` matches the legacy provider shape it falls back to `legacyResolver`; otherwise requests fail with a config error. The header-application matrix lives in a single `(HeaderStyle × AuthMethod)` switch covering OpenAI / Anthropic (`anthropic-version: 2023-06-01`) / Gemini (`x-goog-api-key`) for both API-key and OAuth-bearer auth.

### Notes
- The env-file path keeps working unchanged for existing operators: setting `XALGORIX_LLM` and `XALGORIX_API_KEY` continues to drive scans without touching the catalog or profile store. Catalog and profile writes never modify `~/.xalgorix.env`.
- `/oauth/callback` is intentionally not registered on the dashboard mux — loopback callbacks land on per-flow ephemeral listeners owned by the `pkce` driver.

### See also
Spec: `.kiro/specs/provider-catalog-and-oauth/`

## [Unreleased] — Concurrency model: RAM-only admission

### Changed
- **Scan admission now derives concurrency purely from RAM headroom.** `EffectiveMaxInstances` no longer mixes CPU load and disk pressure into the slot count. CPU saturation throttles scans (the kernel time-slices) but doesn't crash them, so gating new scans on CPU only reduced total throughput. Disk consumption is bursty, not reserved up front; disk now acts as a yes/no admission gate that refuses new scans only when free space is below the critical floor (`XALGORIX_DISK_CRITICAL_MB`, default 1 GB).
- **Per-tool CPU throttling is unchanged** and still lives in the tool-lease layer (`tryAcquireToolLease`), where it correctly queues heavy subprocess launches without blocking scan admission.
- **Dashboard layout.** The "Max N · scan budget · tool cap" caption moved from under the DISK FREE tile to under HOST MEMORY, where the underlying constraint actually lives. DISK FREE now describes its own role.
- **Admission rationale** strings (`/api/status`, the dashboard) only mention dimensions that actually gate admission (RAM and disk-critical). Pre-cleanup, an "instances 4/4 — CPU critical: load X" message was misleading because admission proceeded regardless of CPU.

### Removed
- `XALGORIX_SCAN_CPU_LOAD` env var and its associated `perScanCPULoad` / `autoScanCPULoad` plumbing, the `Capacity().ScanCPULoad` field, the `scan_cpu_load` field on `/api/status`, and the matching settings UI row. The knob hadn't influenced admission since it was a stealth no-op; setting it now logs a one-time deprecation notice on startup.
- Internal `cpuInstanceCapacity` helper (no callers after the refactor).
- Internal `hostMatchesLocalInterface` helper (dead code; `isBlockedTarget` now routes through `ipsMatchLocalInterface`).
- The `level` parameter on `effectiveMaxInstancesForStats` (it was unused after the refactor).

### Fixed
- `effectiveMaxInstancesForStats` no longer calls `memoryInstanceCapacity` twice on the same `stats` snapshot.

## v4.4.19 — Scope guard hardening v2

### Fixed
- **URL-in-query-param bypass closed.** `scopeHostTokenSplit` in `internal/agent/agent.go` now also breaks tokens on `=`, `?`, `#`, and `@`, and a new `extractEmbeddedURLs` sweep pulls every `http://` / `https://` substring out of an arg value before the separator pass. An OOS host smuggled inside a redirect query parameter (e.g. `https://in-scope.example/redirect?next=https://oos.example/path`), a userinfo form (`user@oos.example`, `https://user:pass@oos.example/`), or any of the new delimiters now surfaces as a standalone token and the gated tool call is rejected.
- **Per-arg scan length capped at 8 KiB.** A new `argScanLimitBytes = 8192` constant plus `truncateForScopeScan` helper bound how much of any single Arg_Value the agent-side guard tokenizes. Values ≤ 8 KiB still walk the same path byte-for-byte; values larger than 8 KiB are silently truncated at the largest UTF-8 rune-boundary offset ≤ 8192. The cap never short-circuits to a reject — oversize args fall through to the existing allow path on length alone.
- **Single DNS lookup per `isBlockedTarget` call.** `isBlockedTarget` in `internal/web/server.go` now parses the host as a `net.IP` literal first, otherwise issues exactly one `net.LookupHost` (via a package-level `lookupHost` shim for testability), and threads the resolved IP slice into both the self-listener check (new internal helper `ipsMatchLocalInterface`) and the private-range check. DNS failure preserves the prior `return false` (allow) verdict.
- **OOS hostnames in `add_note` are redacted, not leaked.** A new `(*Agent).redactOutOfScopeHosts` method mirrors the gated tokenization path and substitutes the literal marker `[redacted: out-of-scope host]` for every OOS host span in the `key` and `value` arguments of `add_note`. The agent loop applies redaction in place immediately before `shouldBlockForOutOfScope`, so notes can no longer launder OOS hostnames through `read_notes` on the next iteration. Gated tools continue to reject rather than redact.

### See also
Spec: `.kiro/specs/scope-guard-hardening-v2/requirements.md`

## [Unreleased]

### Breaking changes

#### Default workspace moved to `~/.xalgorix/data/`

The default location for scan output, notes, schedules, and other generated artefacts moved from `$CWD` (the directory the binary was launched from) to `~/.xalgorix/data/`. This is the single most visible part of the stability + workspace-isolation release.

**To retain previous behavior**, run:
```
export XALGORIX_DATA_DIR=$(pwd)
```

A `[MIGRATION]` warning is emitted at startup when legacy markers (`notes.json`, `_schedules/`, `vulnerabilities.json`, or `YYYY-MM-DD/scan-*` directories) are detected in `$CWD` and `XALGORIX_DATA_DIR` is unset.

### Added
- `XALGORIX_LLM_MAX_INFLIGHT`: caps concurrent outbound LLM calls (default: `4 × EffectiveMaxInstances`, minimum 1).
- Health endpoint counters: `panics_recovered`, `path_rejections`, `watchdog_kills`, `admission_refusals`, `llm_inflight_cap`, `data_dir`, `allow_list`, `read_deny`.
- Path_Policy boundary check: every filesystem-touching tool now writes only into `~/.xalgorix/data/`, `~/.xalgorix/`, or `/tmp/`.
- Read-policy: filesystem-touching tools may now READ anywhere on the host (system wordlists, payload directories, `/etc/services`, etc.) so agents can use shared assets without copying them into the workspace. A built-in deny-list still rejects reads of sensitive paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc/shadow`, `/etc/sudoers`, `/proc/kcore`, etc.). Set `XALGORIX_READ_DENY_LIST` (colon-separated) to extend the defaults. The active deny-list is exposed as `read_deny` on `/api/status`.
- Browser tool now acquires Tool_Leases and applies process memory limits.
- Recovery for tool panics, scheduler ticks, HTTP handler panics, and ScanContext close panics.

### Fixed
- Python and terminal tools no longer leak `.tmp/`, `.cache/`, `.config/`, `.local/` directories into `$CWD`. They now create those scratch dirs under the active scan directory or `~/.xalgorix/data/`.
- Tool stdout/stderr now bounded to 1 MB / 512 KB respectively (prevents OOM from runaway output).

### See also
Spec: `.kiro/specs/xalgorix-stability-and-workspace-isolation/requirements.md`

## [Unreleased] — Findings consistency and pagination

### Fixed
- **Findings page no longer truncated to 30 scans.** The Findings dashboard now enumerates every scan on disk and paginates the union with controls for page size [25, 50, 100, 200] (default 50). Findings deduplicate across runs by `(target, endpoint, title, severity)`, with the surviving row linking to the most recent producing scan.
- **Counter flicker eliminated.** The Findings and Overview totals widgets keep prior data during refetches (`keepPreviousData`), so the visible total no longer drops to zero between background polls.
- **Counter monotonicity per scan.** A new `effectiveVulnCount(inst, sess)` helper consolidates the previous triple-source `inst.VulnCount` assignments. Counters now read in-memory while the scan is running and on-disk after teardown — they never visibly drop without a delete.
- **Panic-safe persistence of child findings.** `reporting.PromoteToParent` is invoked on every successful `report_vulnerability` so a child scan's findings reach the parent aggregate immediately. Combined with `MergeVulnsToContext` running in the deferred `cleanup()`, parent records survive child agent panics.

### Added
- **`/api/findings/summary` endpoint.** Returns severity counts derived from on-disk scan records, with an `as_of` timestamp and `etag` for cheap polling. Polled by the WebUI every 10s; honors `If-None-Match` for `304 Not Modified` responses.
- **`vulns_persisted` field in `/api/status`.** Stable on-disk total alongside the existing `vulns` (in-memory) field. Additive change — no breaking change for existing clients.
- **Legacy `~/xalgorix-data/` import.** On first server start after this release, scan records under `~/xalgorix-data/` are non-destructively copied into `cfg.DataDir`. A sentinel file `.legacy-imported` prevents repeated walks. The legacy directory is preserved; you may manually `rm -rf ~/xalgorix-data` after verifying the import via the WebUI banner and Findings page.

### Notes
- The legacy import is intentionally manual to undo. Automation here is out of scope.
- The previous spec's `safe.Recover` wrappers already contain agent-goroutine panics to a single scan; the panic that motivated this work no longer crashes the whole server even before the persistence fixes land. This bugfix focuses on counter and pagination correctness.
