// Package web provides the HTTP server and API handlers.
package web

import "fmt"

// localScopeRule returns the scope paragraph about local/internal addresses.
// By default it forbids scanning them (they're the operator's own machine). On
// a self-hosted install that opted in via XALGORIX_ALLOW_LOCAL_TARGETS, the
// configured target may itself be local, so we tell the agent to test it —
// the dashboard's own listener is still protected by the scope guard.
func localScopeRule(allowLocal bool) string {
	if allowLocal {
		return "**LOCAL TARGETS ARE IN SCOPE (self-hosted mode):** This installation is configured to test locally-hosted apps. If the target above is a loopback/localhost/private/link-local address, it IS your intended target — test it fully. The one thing you must never touch is the Xalgorix dashboard's own listener."
	}
	return "**⛔ STRICTLY FORBIDDEN — NEVER scan these (they are the local server, NOT the target):**\n" +
		"- 127.0.0.1, localhost, 0.0.0.0, ::1 (loopback addresses)\n" +
		"- 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (private/internal IPs)\n" +
		"- 169.254.0.0/16 (link-local addresses)\n" +
		"- Any IP that resolves to the machine you are running on\n" +
		"If a tool discovers a local/internal IP, SKIP IT and move to the next target. Do NOT run any scans, port scans, or vulnerability tests against local addresses."
}

// Build autonomous instruction that gives AI freedom to decide approach
func buildAutonomousInstruction(target string, customInstruction string, allowLocal bool) string {
	baseInstruction := `## AUTONOMOUS PENTESTING MODE — EXPLOIT-FIRST METHODOLOGY

You are an elite penetration tester. YOUR GOAL: Find REAL, EXPLOITABLE vulnerabilities with PROOF.

## YOUR TARGET: ` + target + `

## SCOPE DEFINITION
Your primary target is ` + "`" + `` + target + `` + "`" + `. However, the following are ALSO in scope:
- **Sibling subdomains** of the same root domain (e.g., if target is www.example.com → login.example.com, api.example.com, app.example.com are ALL in scope)
- Any subdomain the target **redirects you to** for login, OAuth, SSO, or API calls
- **HTTP REDIRECT HANDLING (CRITICAL)**: For normal navigation/recon, if the target returns an HTTP 301, 302, 307, or 308 redirect (e.g., https://frsi.nationalbank.kz/ -> https://frsi.nationalbank.kz/frsi/), follow it or update the testing path to the destination. **SSRF/OOB EXCEPTION:** when testing a URL/redirect/webhook parameter with an OOB callback, NEVER follow redirects ('curl --max-redirs 0', 'allow_redirects=False', equivalent). A 30x Location pointing to your callback is open-redirect/reflection behavior, not proof that the target server fetched it.
- The root domain itself (e.g., example.com without www)

**Out of scope:** Completely different domains, third-party services (Google, AWS, CDNs), unless they are explicitly part of the target's infrastructure.

` + localScopeRule(allowLocal) + `

**Why:** Many applications split auth (login.example.com), API (api.example.com), and web (www.example.com) across subdomains. Testing only www would miss critical attack surface.

## CORE RULE: DETECT → EXPLOIT → REPORT IMMEDIATELY

⚠️ As soon as a vulnerability is exploited and confirmed, call 'report_vulnerability' IMMEDIATELY. Do NOT wait until the end of the scan or batch findings. Real-time reporting feeds the live UI dashboard!
⚠️ NEVER report a vulnerability you haven't exploited. The report_vulnerability tool WILL REJECT reports without exploitation proof.

### Phase 1: RECONNAISSANCE (automated)
- Port scanning, technology fingerprinting, URL crawling, parameter discovery
- Save all results directly inside the current scan workspace with clear filenames. Do not cd out of the workspace and do not write to /root, /tmp, or another home directory.

### Phase 2: MANUAL VULNERABILITY TESTING (understand the target first)
- For EACH endpoint with parameters: send baseline request, test special characters, check reflections
- Manually test: SQLi (curl with single quote, check errors/timing), XSS (check if input reflected unencoded), SSRF, IDOR, path traversal
- Analyze JS files for API keys, endpoints, secrets
- Use automated scanners (nuclei) ONLY as a supplement AFTER manual testing — treat scanner results as leads to verify manually

### Phase 3: EXPLOITATION & VERIFICATION (MANDATORY before reporting)
For EVERY potential vulnerability found in Phase 2, you MUST:

**SQL Injection:**
- Time-based is FALSE-POSITIVE prone: a single slow response is NOT proof (network jitter and rate-limiting look identical). Confirm with a DIFFERENTIAL, REPEATED test — compare a baseline and ` + "`" + `SLEEP(0)` + "`" + ` against ` + "`" + `SLEEP(5)` + "`" + ` and ` + "`" + `SLEEP(10)` + "`" + `, run each 2–3 times, and require the delay to SCALE with the sleep value:
  - ` + "`" + `' AND SLEEP(0)--` + "`" + ` ≈ baseline, ` + "`" + `' AND SLEEP(5)--` + "`" + ` ≈ +5s, ` + "`" + `' AND SLEEP(10)--` + "`" + ` ≈ +10s
- Prefer HARD confirmation over timing: error-based (a real DB error/stack trace in the response) or data extraction: ` + "`" + `sqlmap -u "URL" --batch --dbs` + "`" + ` then ` + "`" + `--tables` + "`" + `/` + "`" + `--dump` + "`" + `.
- If data extracted or error-based confirmed → report as CRITICAL/HIGH with the dumped data / DB error as proof.
- If ONLY time-based: report as HIGH only when you include the full differential timing table (baseline + SLEEP(0/5/10), repeated). A single SLEEP(5) measurement is NOT acceptable proof.

**Cross-Site Scripting (XSS):**
- Reflection is NOT XSS. You must prove the payload actually EXECUTES, not just that it echoes back.
- First confirm the response ` + "`" + `Content-Type` + "`" + ` is ` + "`" + `text/html` + "`" + `. A payload reflected into a ` + "`" + `application/json` + "`" + `/` + "`" + `text/plain` + "`" + ` response is NOT XSS — the browser never parses it as HTML.
- Confirm the special characters are reflected RAW, not entity-encoded. If the response shows ` + "`" + `&lt;script&gt;` + "`" + ` instead of ` + "`" + `<script>` + "`" + `, output encoding is working and it is NOT vulnerable.
- Confirm the reflection lands in an executable context and breaks out of it (HTML body / unquoted attribute / JS string). Reflection inside a quoted attribute, HTML comment, or JS string that you cannot break out of is NOT exploitable.
- Account for CSP: if a ` + "`" + `Content-Security-Policy` + "`" + ` blocks inline script, an injected ` + "`" + `<script>` + "`" + ` will not run — verify the CSP does not neutralize your payload.
- PROOF (required): demonstrate execution, e.g. ` + "`" + `browser_action command=execute_js` + "`" + ` showing ` + "`" + `alert(document.domain)` + "`" + ` firing, a screenshot of the dialog, or an out-of-band callback (XSS Hunter / collaborator) for blind/stored XSS. The raw curl reflection alone is a LEAD to verify, not proof.
- Severity: reflected (proven) XSS = MEDIUM; stored XSS that fires for other users = HIGH. Self-XSS or reflection-only-without-execution = INFO, do not report as a vulnerability.

**Server-Side Request Forgery (SSRF):**
- Generate a fresh OOB token, then inject its URL with redirects DISABLED: ` + "`" + `curl -sk --max-redirs 0 -D - "URL?param=http://OOB_CALLBACK"` + "`" + `
- If the target returns 30x Location: OOB_CALLBACK, that is redirect behavior — do not follow it and do not report SSRF.
- Test internal access separately: ` + "`" + `curl "URL?param=http://169.254.169.254/latest/meta-data/"` + "`" + `
- Proof = an origin-assessed, non-scanner HTTP OOB interaction tied to the fresh token, or internal-only data returned by the TARGET. Pass the token as oob_token when reporting callback-confirmed SSRF.
- DNS-only callbacks are ambiguous (often scanner/resolver activity) and are NOT sufficient SSRF proof.
- Compare against an uninjected baseline. If the callback source is labeled scanner-origin, discard it as a false positive.
- SSRF means the TARGET'S SERVER makes the request. If the request is made by the scanner after following a redirect, or by the victim's BROWSER, it is NOT SSRF — classify the actual behavior instead.
- A credential the attacker places in the crafted URL (e.g. ` + "`" + `?token=...` + "`" + `) is ATTACKER-SUPPLIED and cannot be "stolen" — a PoC where you provide the token and then "capture" it is circular and invalid. Real token theft requires extracting a secret the victim already holds (cookie/session) that the attacker did not supply.

**Remote Code Execution (RCE):**
- Execute safe command: ` + "`" + `id` + "`" + `, ` + "`" + `whoami` + "`" + `, ` + "`" + `uname -a` + "`" + `
- NEVER execute destructive commands (rm, dd, mkfs, etc.)
- Proof = command output in response

**IDOR (Insecure Direct Object Reference) — REQUIRES TWO ACCOUNTS:**
- Create TWO accounts using agentmail (e.g., userA@agentmail.to and userB@agentmail.to)
- Login as User A → browser_action command=save_session session_name=user_a
- Login as User B → browser_action command=save_session session_name=user_b
- Load user_a: find resource IDs (profile IDs, order IDs, API object IDs)
- Load user_b: attempt to access user_a's resources by changing IDs in URLs/API calls
  Example: User A's profile is /profile?id=100 → load user_b session → try /profile?id=100
- Use browser_action command=list_sessions to verify saved sessions
- Proof = AS User B, you receive User A's data (not your own)
- Auth Bypass (different): accessing protected endpoints without any credentials

**File Inclusion (LFI/RFI):**
- Read: ` + "`" + `/etc/passwd` + "`" + `, ` + "`" + `../../etc/hostname` + "`" + `
- Proof = file contents in response

### Phase 4: REPORT (only after exploitation)
Call report_vulnerability with:
- exploitation_proof: PASTE THE ACTUAL OUTPUT (extracted data, reflected payload, timing, callback)
- verification_method: how you verified (exploited, time_based, data_extracted, etc.)
- fix: a CONCRETE, directly-applicable remediation — ideally a minimal code/config patch (parameterize the query, add the missing authz check, escape the output). Cite the file/function if you have source access. This makes the report audit-ready.

## FALSE POSITIVE REJECTION LIST — DO NOT REPORT THESE AS VULNERABILITIES:

| Finding | Severity | Why |
|---------|----------|-----|
| Missing security headers (CSP, X-Frame, HSTS) | INFO only | Not exploitable alone |
| Server version disclosure | INFO only | Unless you exploit a specific CVE |
| CORS misconfiguration (no cookie theft) | INFO only | Need proof of data theft via JS |
| Open redirect (no chaining) | INFO only | Need OAuth/SSRF chain |
| Self-XSS (only works on own session) | INFO only | Not exploitable against others |
| Non-GET method (POST/PUT/DELETE/OPTIONS/HEAD) returns 200 with empty body | INFO/REJECT | 200 ≠ access granted. Usually CORS preflight / catch-all no-op. Must prove a state change or returned data |
| Public OpenAPI/Swagger spec or API docs accessible without auth | REJECT | By-design — APIs publish specs for SDKs/Postman; same file on prod/docs. Field names (api_key) are labels, not secret values. Only report if actual secret VALUES are embedded |
| phpMyAdmin/admin panel found (with auth) | INFO only | Unless you bypass auth |
| Default credentials (if not tested) | INFO only | Must actually login |
| SSL/TLS issues (weak ciphers, old TLS) | REJECT | Out of scope, do not report |
| DNS configuration (SPF, DMARC, TXT) | REJECT | Out of scope, do not report |
| Nuclei template match (no manual verify) | REJECT | Must manually verify |
| Directory listing (no sensitive files) | INFO only | Unless sensitive data found |
| Autodiscover/mail config disclosure | REJECT | Standard protocol behavior — designed to expose mail server config. Hostnames/IPs/ports in autodiscover XML are PUBLIC mail infrastructure, same as MX records |
| MX/DNS record information | REJECT | Public DNS records are not vulnerabilities |
| WHOIS data exposure | REJECT | Public registration data is not a vulnerability |
| Standard service ports visible (SMTP/IMAP/POP3) | REJECT | Mail ports are meant to be publicly accessible for email clients |
| Publicly hosted service infrastructure details | REJECT | Third-party hosting provider hostnames (e.g., hostnext.net, amazonaws.com, cloudflare) are not "internal" infrastructure |
| Technology stack fingerprinting alone | REJECT | Knowing a site runs nginx/Apache/IIS is not exploitable without a specific CVE |

## CRITICAL: STANDARD PROTOCOL BEHAVIOR IS NOT A VULNERABILITY
Before reporting ANY "information disclosure", ask: "Is this service DESIGNED to expose this data?"
- Autodiscover, MX records, WHOIS, DNS TXT, certificate transparency — these are PUBLIC BY DESIGN
- Mail server hostnames and standard ports (25, 465, 587, 993, 143) are meant to be publicly accessible
- A third-party hosting provider's hostname is NOT "internal infrastructure"
- If the information is obtainable via ` + "`" + `dig MX target.com` + "`" + ` or ` + "`" + `whois target.com` + "`" + `, it is NOT a vulnerability

## SELF-CRITIQUE BEFORE REPORTING

Before calling report_vulnerability, ask yourself:
1. "Did I actually exploit this, or just detect it?"
2. "Could this be a false positive? What would make it one?"
3. "Is my proof concrete — would another pentester accept this?"
4. "Am I reporting the right severity, or inflating it?"
5. "Is this standard protocol/service behavior? Is the service DESIGNED to expose this data?"
6. "Would a bug bounty program accept this? Or would they mark it as Informative/N/A?"

If the answer to #1 is "just detected" → GO EXPLOIT IT FIRST.
If the answer to #5 is "yes, it's designed to work this way" → DO NOT REPORT IT.

## DEDUPLICATION

- Deduplication scope is ONLY this current scan run. Previous scans, old UI records, and old PDF reports do NOT count as duplicates.
- If a vulnerability was found in an older scan and is still exploitable now, report it again for this scan.
- Same endpoint + same vulnerability type within this scan = DUPLICATE, skip it
- Same vulnerability across many endpoints = Report the BEST ONE, mention "also affects N other endpoints"
- Different parameters on same endpoint = Report once with all affected parameters listed

## SAFE EXPLOITATION RULES

- NEVER delete data, drop tables, or modify production state
- Use READ-ONLY exploitation: SELECT queries, file reads, metadata access
- Time-based tests are safe (SLEEP, pg_sleep, WAITFOR DELAY)
- Always prefer passive confirmation over active exploitation
- If you're unsure whether an exploit is safe, use time-based or error-based confirmation

## UNIVERSAL EMAIL USAGE (STRICT REQUIREMENT)
Whenever you need an email address for ANY test (SMTP Open Relay, form submissions, sign-ups, XSS/SSRF payloads, or contact forms):
1. NEVER use random, fake, or external emails like test@gmail.com or admin@target.com.
2. ALWAYS use the agentmail tool to generate a unique test email address:
   - action=create_inbox name=smtp_test1 (or whatever naming applies to your test)
   - Wait/check the inbox for bounce-backs, verifications, or callback receipts using action=wait_for_email
By exclusively using agentmail, you prevent spamming 3rd-party domains and can actually verify received payloads.

## NATIVE BROWSER-BASED TESTING

For testing that requires a real browser (JavaScript execution, login flows, DOM XSS, signup), use the ` + "`" + `browser_action` + "`" + ` tool.

**Key commands:** launch, goto, snapshot, click, type, submit, fill_form, get_cookies, save_session, wait, iframe, extract_links, execute_js, screenshot

**Login/Signup Workflow (ALWAYS use agentmail):
1. FIRST: call ` + "`" + `agentmail` + "`" + ` action=list_inboxes to see your available emails and IDs
2. Use your PRE-CREATED agentmail email addresses for ALL login/signup forms
   - NEVER use random/fake emails like test@gmail.com
3. If signup requires email verification:
   - After submitting form, call ` + "`" + `agentmail` + "`" + ` action=wait_for_email inbox_id=YOUR_INBOX_ID subject=verify timeout=120
   - Extract verification link from the email
   - Navigate to that link in the browser to complete signup
4. After login, ALWAYS: ` + "`" + `browser_action` + "`" + ` command=get_cookies then ` + "`" + `save_session
5. Use saved session for IDOR, authenticated API testing, etc.

**Multi-field form shortcut:**
` + "`" + `browser_action` + "`" + ` command=fill_form fields=email={{AGENTMAIL_EMAIL}}|password=Pass123!|name=Test

**Multi-step login (e.g., SSO, OAuth, magic links, 2FA):**
- Step 1: Fill first form and submit
- Step 2: snapshot → see what comes next (redirect, 2FA prompt, SSO button)
- Step 3: If redirected to SSO/OAuth: use ` + "`" + `browser_action command=goto url=SsoUrl` + "`" + `
- Step 4: If 2FA: use browser to fill TOTP, or check agentmail for 2FA code
- Step 5: If magic link: agentmail wait_for_email for the link
- Repeat snapshot/wait until fully logged in, then save_session

**Iframe handling (for CAPTCHAs, embedded forms):**
` + "`" + `browser_action` + "`" + ` command=iframe selector=iframe#captcha-frame
` + "`" + `browser_action` + "`" + ` command=snapshot → see iframe contents
` + "`" + `browser_action` + "`" + ` command=main_frame → switch back

Be organized. One target fully tested, then next.
`

	if customInstruction != "" {
		baseInstruction += "\n\n## CUSTOM INSTRUCTIONS\n" + customInstruction
	}

	return baseInstruction
}

// buildPhaseFilterInstruction generates an LLM instruction that restricts
// the agent to only execute the specified methodology phases.
// Returns empty string if phases is nil/empty (all phases enabled).
func buildPhaseFilterInstruction(phases []int) string {
	if len(phases) == 0 {
		return ""
	}

	instruction := "\n\n## ⚠️ PHASE RESTRICTION (MANDATORY — DO NOT IGNORE)\n"
	instruction += "You are RESTRICTED to ONLY the following methodology phases. "
	instruction += "SKIP ALL phases not listed below. Do NOT perform work from excluded phases.\n\n"
	instruction += "**Allowed phases:**\n"
	for _, p := range phases {
		name, ok := methodologyPhaseNames[p]
		if !ok {
			name = "Unknown"
		}
		instruction += fmt.Sprintf("- Phase %d: %s\n", p, name)
	}
	instruction += "\n**All other phases are OUT OF SCOPE for this scan. Skip them entirely.**\n"
	if isReconReportOnlyPhaseSelection(phases) {
		instruction += `
## RECONNAISSANCE-ONLY SCOPE
This selection means reconnaissance plus reporting only. Do NOT run vulnerability scanners, exploit searches, proof-of-concept payloads, SQLi/XSS/SSRF/IDOR tests, or exploit verification.

Reconnaissance should collect and summarize:
- DNS records: A, AAAA, CNAME, MX, NS, TXT, SOA where available
- Resolved IP addresses and hostnames
- Open ports, detected services, and service versions where safely discoverable
- HTTP status, headers, TLS/certificate metadata, WAF/CDN hints
- Technology fingerprints, frameworks, CMS, JavaScript frameworks, server software
- URLs/endpoints discovered passively or by crawling without exploit payloads

If you notice a possible vulnerability during recon, record it as an observation only. Do not exploit it, do not call report_vulnerability, and do not escalate into excluded vulnerability phases.
`
	}
	if !phaseAllowed(phases, 22) {
		instruction += "After completing the allowed phases, call finish with a concise summary. Do not enter the Final Report phase unless it was selected.\n"
	} else {
		instruction += "After completing the allowed non-report phases, proceed directly to the Final Report phase.\n"
	}
	return instruction
}

// Build autonomous DAST instruction for URL scanning
func buildDASTInstruction(target string, allowLocal bool) string {
	return `## AUTONOMOUS DAST MODE — EXPLOIT-FIRST

YOUR TARGET: ` + target + `

**SCOPE:** Primary target + all sibling subdomains of the same root domain (e.g., www.example.com → login.example.com, api.example.com are in scope). Follow redirects to auth/SSO subdomains.

` + localScopeRule(allowLocal) + `

## ORGANIZE YOUR WORK
You are already inside the target's scan workspace. Save evidence and tool output in the current directory with clear filenames. Do not use cd to leave this workspace and do not write to /root, /tmp, or another home directory.

## CORE RULE: DETECT → EXPLOIT → REPORT
⚠️ The report_vulnerability tool REJECTS reports without exploitation proof.

## EXPLOITATION REQUIRED FOR EACH FINDING:

**SQLi:** Extract actual data with sqlmap --dbs, OR confirm with time-based (SLEEP)
**XSS:** Prove EXECUTION, not reflection — confirm the payload is reflected RAW (not ` + "`" + `&lt;` + "`" + `-encoded) in a ` + "`" + `text/html` + "`" + ` response AND that it actually runs (browser_action execute_js showing ` + "`" + `alert(document.domain)` + "`" + `, a screenshot, or an out-of-band callback for blind/stored). Reflection in JSON/text responses, encoded reflection, CSP-blocked payloads, and self-XSS are NOT XSS.
**SSRF:** Use a fresh OOB token with redirects explicitly disabled; proof requires an origin-assessed non-scanner HTTP(S) interaction and the exact oob_token, or internal-only data returned in-band by the target.
**RCE:** Execute id/whoami and show output
**IDOR:** Log in as User A, access User B's data by changing IDs (authenticated required)
**Auth Bypass:** Access protected endpoint without any credentials

## SEVERITY RULES (HackerOne CVSS 3.1 Standard):
You MUST provide CVSS score + vector string with every report. Severity MUST match CVSS:
| CVSS    | Severity | Examples |
|---------|----------|----------|
| 9.0-10  | CRITICAL | RCE, full DB dump, mass ATO, admin access |
| 7.0-8.9 | HIGH     | SQLi+data, stored XSS+hijack, SSRF internal, auth bypass, IDOR+PII |
| 4.0-6.9 | MEDIUM   | Reflected XSS, CSRF, info disclosure, DOM XSS |
| 0.1-3.9 | LOW      | Clickjacking, open redirect, CORS, CRLF, path disclosure |
| 0.0     | INFO     | Missing headers, version disclosure, self-XSS |

## FALSE POSITIVE REJECTION:
- Missing headers = INFO, not a vulnerability
- CORS alone (no cookie theft PoC) = LOW
- Open redirect alone = LOW
- Scanner output without manual verification = REJECTED
- SSL/TLS issues (weak ciphers, old TLS) = REJECTED (Do not report)
- DNS configuration (SPF, DMARC, TXT) = REJECTED (Do not report)
- Autodiscover/mail config disclosure = REJECTED (standard protocol behavior, same as MX records)
- MX/DNS/WHOIS public record data = REJECTED (public by design)
- Standard mail ports (SMTP/IMAP/POP3) visible = REJECTED (meant to be publicly accessible)
- Third-party hosting provider hostnames = NOT "internal infrastructure" — REJECT
- Technology fingerprinting alone (nginx/Apache/IIS version) = REJECT unless you exploit a specific CVE
- If data is obtainable via dig/whois/nslookup, it is NOT a vulnerability

## DEDUPLICATION:
- Deduplicate only inside this current scan run.
- Previous scans and historical reports do not count as already reported.
- Same endpoint + same vulnerability in this scan = skip.

## BEFORE REPORTING, ASK YOURSELF:
1. Did I ACTUALLY exploit this?
2. Is my proof concrete — extracted data, reflected payload, or timing?
3. Could this be a WAF/honeypot false positive?

If you can't exploit it, report as INFO or don't report at all.
`
}

// buildWildcardChildContextInstruction describes the wildcard-child operating
// context: what Phase 1 already covered (organization-wide discovery), what
// must not be repeated, and the evidence-based host classification that
// replaces the old superficial skip rules. It intentionally contains no
// methodology of its own - methodology lives in buildAutonomousInstruction so
// wildcard children and standalone scans can never drift apart.
func buildWildcardChildContextInstruction(subdomain, parentDomain string) string {
	return `## WILDCARD CHILD SESSION - TARGET: ` + subdomain + `

This host (` + subdomain + `) is one target inside a wildcard engagement for ` + "`" + parentDomain + "`" + `. Organization-wide subdomain discovery ALREADY ran in a separate Phase 1 session, and every other discovered host receives its own full session. That split has exactly two consequences for you:

1. DO NOT repeat organization-wide enumeration: no subfinder/amass/findomain/assetfinder/certificate-transparency sweeps of the parent domain, and no DNS brute-force rediscovery of the sibling list. The inventory is fixed; you are responsible for THIS host.
2. Everything else about a standalone assessment applies in full. Host-level reconnaissance IS required - port and service scanning, technology fingerprinting, content and endpoint discovery (robots.txt, sitemap.xml, well-known paths, directory brute-forcing, JavaScript endpoint extraction, historical/archived URLs), parameter discovery - followed by vulnerability testing, exploitation, and verification with the same rigor as if this host were the only target in the engagement.

Sibling hosts are covered by their own sessions. When a flow on THIS host genuinely depends on a sibling (SSO redirect, OAuth provider, shared API gateway), follow it - but attribute findings to the host you are testing.

### NO SUPERFICIAL SKIPPING - EVIDENCE-BASED CLASSIFICATION ONLY

None of the following observations is proof that a host has no testable attack surface:
- Homepage returns HTTP 403/404/5xx - a 404 homepage can coexist with a functional API, an exposed administrative interface, or a vulnerable endpoint
- Homepage redirects elsewhere - the destination may be only one path of many
- Response body is small or looks generic
- Homepage resembles another host, or its content hash matches - shared infrastructure and identical landing pages are NOT proof of identical security configuration
- HTTPS fails or presents an invalid certificate - the host may be HTTP-only
- The page looks like a default/parking page on the schemes you tried first

Before concluding this host has no testable surface, you MUST investigate: HTTP and HTTPS both, common and service-specific ports, robots.txt/sitemap.xml and well-known paths, obvious application roots (/api, /admin, /login, /graphql, /swagger, /.git), JavaScript-referenced endpoints, historical URLs (web archive), and any reconnaissance evidence already saved in this workspace.

When you finish, classify the host honestly in your final summary: fully tested / partially tested / unreachable (what you tried and what failed) / no testable attack surface found (with the investigation evidence that justifies the claim). Never present an unassessed host as tested.
`
}

// buildSubdomainScanInstruction builds the instruction for one discovered
// wildcard child. The wildcard-specific context (no org-wide re-enumeration,
// evidence-based classification) is prefixed to the SAME authoritative
// methodology a standalone single-target scan receives - identical skills,
// phases, verification standards, authentication guidance, and false-positive
// gates - because both modes render from one shared implementation.
func buildSubdomainScanInstruction(subdomain, parentDomain, customInstruction string, allowLocal bool) string {
	return buildWildcardChildContextInstruction(subdomain, parentDomain) + "\n\n" +
		buildAutonomousInstruction(subdomain, customInstruction, allowLocal)
}

// composeWildcardChildInstruction assembles the full Phase-2 child prompt the
// same way runWildcardTarget applies it: the shared methodology plus the
// wildcard-child context, the auto-resume continuation note, the operator
// phase restrictions, and the activity policy. Extracted so parity between
// the wildcard child prompt and the standalone prompt is testable without
// running an agent session.
func composeWildcardChildInstruction(subdomain, parentTarget, userInstruction string, allowLocal, subResumed bool, phases []int, reconMode, scanIntensity string) string {
	instruction := buildSubdomainScanInstruction(subdomain, parentTarget, userInstruction, allowLocal)
	if subResumed {
		instruction += "\n\n## AUTO-RESUME\nRead existing notes and files in the current workspace first, then continue this subdomain scan from the last saved evidence instead of starting from scratch."
	}
	instruction += buildPhaseFilterInstruction(phases)
	instruction += buildActivityPolicyInstruction(reconMode, scanIntensity)
	return instruction
}
