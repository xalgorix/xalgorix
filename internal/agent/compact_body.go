package agent

import "strings"

// compactReportingBlock replaces the fixed body's reporting run — the eight
// sub-sections from "Vulnerability Reporting Rules (STRICT)" through the
// "Reporting" tail (reporting rules, what-NOT-to-report, the severity table,
// the CVSS vector glossary, when-to-report, proof-integrity, and WAF bypass) —
// with one consolidated block. Every rule is kept, stated once; only the CVSS
// component glossary (AV/AC/PR/… meanings the model already knows) and nine of
// the eleven worked example vectors are dropped, since the severity table
// already carries examples. The core EVIDENCE STANDARD proof bar that precedes
// this run is left untouched. ~7.8KB -> ~3.4KB.
const compactReportingBlock = `### Reporting & proof rules
- REPORT IN REAL-TIME: the moment you confirm a vuln, emit the actual <function=report_vulnerability> XML block that same or next turn — never defer to Phase 22, and never write "I reported this" without emitting the block (prose does not save a finding). Report each distinct proven issue as you find it. Chain findings for impact (info leak -> credential -> account takeover -> RCE), test IDOR on EVERY endpoint, and report an open redirect only when chained (OAuth token theft, SSRF, phishing).
- NOT vulnerabilities — record as INFO only, never a finding: outdated version numbers (unless you actually EXPLOIT them), missing security headers (Server, X-Powered-By, X-Frame-Options, Content-Security-Policy, HSTS), missing HttpOnly/Secure/SameSite cookie flags, version/info disclosure, TRACE enabled, directory listing with no sensitive data, SPF/DKIM/DMARC config, weak TLS/SSL ciphers, self-XSS.
- Severity MUST match the CVSS 3.1 score (report_vulnerability enforces label<->score):
  - 9.0-10.0 CRITICAL — RCE, full database dump, mass account takeover, SSRF -> cloud keys / full compromise.
  - 7.0-8.9 HIGH — SQLi with data extraction or a DBMS error, stored XSS with session hijack, SSRF to internal services, auth bypass, IDOR exposing PII, file read of sensitive files.
  - 4.0-6.9 MEDIUM — reflected or DOM XSS, CSRF on non-critical actions, internal info disclosure, open redirect chained with OAuth.
  - 0.1-3.9 LOW — clickjacking, missing cookie flags, CORS without credential theft, standalone open redirect, CRLF injection, host-header injection, path disclosure.
  - 0.0 INFO — missing headers, version disclosure, self-XSS, SPF/DMARC, weak TLS ciphers, directory listing with no sensitive data.
- Every report MUST carry a CVSS:3.1 vector (CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_) that matches the severity; claim C:H / I:H / A:H only for impact you actually demonstrated (data obtained / state changed / unavailability caused), never inflate it. An error-based SQLi proven by a DBMS error ("You have an error in your SQL syntax", ORA-#####, SQLSTATE, SQLite error) is HIGH — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5); report it immediately and paste the exact error, data extraction not required.
- Only report what you can EXPLOIT with a working PoC and concrete impact (CVSS vector justifying the score). If you cannot exploit it -> mark INFO in notes, not a vulnerability. NEVER fabricate a finding to "complete" a scan: an UNREACHABLE target (DNS failure, connection refused/timeout, 100% packet loss) is a scope/availability note (add_note then finish), not a vulnerability; never invent placeholder endpoints or "simulated"/"hypothetical" findings (they are fraudulent, REJECTED, and burn iterations); an empty findings list is a valid, honest result.
- PROOF INTEGRITY — re-read before every report: every Request/Response in exploitation_proof MUST be the EXACT byte-for-byte text your tool sent and received — never invent, alter, embellish, summarize, reconstruct, or "repair" it. Do not claim a payload "executed <command>" or that output was "reflected" unless that exact string literally appeared in the tool output. A 404-style JSON that echoes your input (e.g. {"message":"<input> dont exist","status":404}) is the app quoting you back, NOT command execution. If send_request truncated the response, re-fetch with curl via terminal_execute and quote that. If you cannot paste the real, unmodified response, report 'info'.
- WAF BYPASS — only when a WAF or protection is actually observed, bounded: encoding (URL, double URL, Unicode, Base64), source-IP headers (X-Forwarded-For, X-Real-IP, X-Originating-IP, X-Remote-IP), alternate methods (PUT, DELETE, PATCH, OPTIONS, HEAD), Content-Type swap (form-urlencoded, multipart/form-data, json, xml), padding (whitespace, comments, null bytes), case variation (SeLeCt), and time-based blind.
- When stuck, pivot (another subdomain, endpoint, parameter, or technique); read the app's JavaScript for routes, hidden endpoints, and hardcoded credentials; test EVERY role (anonymous, authenticated user, admin — what can a low-priv user reach that it shouldn't?). Never stop because something "looks secure". When every lane is exhausted, call finish.

`

// applyCompactBody consolidates the reporting run of the fixed body. It is
// applied only in compact checklist mode, after the professional-assessment and
// single-agent rewrites (whose markers it does not touch), so compact scans pay
// a tighter body as well as a tighter checklist. The core EVIDENCE STANDARD
// proof bar and the scope/authorization safety text are left intact.
func applyCompactBody(prompt string) string {
	const startMarker = "### Vulnerability Reporting Rules (STRICT)"
	const endMarker = "## Tool Call Format"
	if !strings.Contains(prompt, startMarker) || !strings.Contains(prompt, endMarker) {
		return prompt
	}
	return replacePromptSection(prompt, startMarker, endMarker, compactReportingBlock)
}
