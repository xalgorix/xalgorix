// Package reporting provides vulnerability reporting tools with exploit-before-report validation.
package reporting

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	oobsrv "github.com/xalgord/xalgorix/v4/internal/oob"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// sleepMagnitudeRe extracts the numeric argument of SLEEP/pg_sleep/WAITFOR-style
// delays from timing-SQLi proof, so we can tell a single-shot test (one
// magnitude) from a real differential test (two or more distinct magnitudes).
var sleepMagnitudeRe = regexp.MustCompile(`(?:sleep|pg_sleep|delay)\s*[('"\[:\s]\s*0*(\d+)`)
var cveIDRe = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,7}\b`)

// Valid verification methods — the agent must specify one when reporting.
var validVerificationMethods = map[string]bool{
	"exploited":         true, // Full exploitation with proof
	"time_based":        true, // Time-based blind confirmation (SQLi, command injection)
	"data_extracted":    true, // Actual data was extracted
	"callback_received": true, // SSRF/XXE/RCE callback received
	"error_based":       true, // Error-based confirmation (SQL error, stack trace)
	"blind_confirmed":   true, // Blind vulnerability confirmed via side-channel
	"reflected":         true, // Payload reflected in response (XSS)
	"authenticated":     true, // Auth bypass / IDOR with evidence
	"manual_verified":   true, // Manually verified via browser / curl
}

// Minimum evidence keywords per severity — used for auto-downgrade heuristics.
var evidenceKeywords = map[string][]string{
	"critical": {"rce", "remote code", "shell", "reverse shell", "command execution", "dump", "database",
		"full access", "admin takeover", "account takeover", "full compromise", "root access",
		"aws key", "secret key", "private key", "all user", "mass data"},
	"high": {"sqli", "sql injection", "data extract", "xss", "cross-site", "ssrf", "idor",
		"auth bypass", "session hijack", "file inclusion", "pii", "credit card",
		"password hash", "api key", "access token", "privilege escalation"},
	"medium": {"reflected", "csrf", "redirect", "disclosure", "injection", "traversal",
		"internal ip", "internal path", "config", "source code", "debug", "stack trace"},
}

// Vulnerability represents a found vulnerability.
type Vulnerability struct {
	ID                string  `json:"id"`
	Title             string  `json:"title"`
	Severity          string  `json:"severity"`
	OriginalSeverity  string  `json:"original_severity,omitempty"` // if auto-downgraded
	Description       string  `json:"description"`
	Impact            string  `json:"impact"`
	Target            string  `json:"target"`
	Endpoint          string  `json:"endpoint"`
	Method            string  `json:"method"`
	CVE               string  `json:"cve"`
	CWE               string  `json:"cwe_id,omitempty"` // e.g. "CWE-79"
	OWASP             string  `json:"owasp,omitempty"`  // e.g. "A03"
	CVSS              float64 `json:"cvss"`
	CVSSVector        string  `json:"cvss_vector,omitempty"` // CVSS 3.1 vector string
	TechnicalAnalysis string  `json:"technical_analysis"`
	PoCDescription    string  `json:"poc_description"`
	PoCScript         string  `json:"poc_script_code"`
	Remediation       string  `json:"remediation_steps"`
	// Fix is a CONCRETE remediation patch — ideally a minimal code/config diff
	// (e.g. parameterize a query, add an authz check, escape output). This is
	// what makes a report actionable/audit-ready, and mirrors the inline-patch
	// suggestion of leading platforms. Distinct from the prose Remediation.
	Fix                string `json:"fix,omitempty"`
	ExploitationProof  string `json:"exploitation_proof"`
	VerificationMethod string `json:"verification_method"`
	Verified           bool   `json:"verified"`
	// Tags are machine-readable labels surfaced in the UI and report. The
	// verification dimension is always present, one of three states:
	//   TagVerified      — the independent Verifier re-reproduced the finding.
	//   TagExploitProven — the Verifier didn't re-confirm (inconclusive/absent),
	//                      but the agent's OWN proof shows a concrete exploitation
	//                      outcome (command output, extracted data, OOB callback),
	//                      so it stands as proven — not a guess.
	//   TagManualReview  — no concrete proof yet; preserved (not dropped) but must
	//                      be human-confirmed before it's relied on.
	Tags      []string `json:"tags,omitempty"`
	Timestamp string   `json:"timestamp"`
	AgentName string   `json:"agent_name"`
}

// Finding tags (verification dimension). Exactly one is attached to every
// finding so the UI/report can show its confidence at a glance.
const (
	TagVerified      = "verified"                  // independently reproduced by the Verifier
	TagExploitProven = "exploit-proven"            // concrete first-party exploitation proof (verifier inconclusive/absent)
	TagManualReview  = "needs-manual-verification" // no concrete proof yet — human-confirm before relying on it
)

// ── Independent finding verification ──
// A dedicated, distinct-purpose Verifier agent (injected by the agent package
// to avoid an import cycle) independently re-tests every actionable candidate
// finding (low severity and above; only 'info' is exempt) BEFORE it is
// persisted. This is the core of Xalgorix's "real validation, not just
// detection" guarantee: a finding that the verifier cannot independently
// reproduce is never presented as validated.

// VerificationRequest is the candidate finding handed to the verifier.
type VerificationRequest struct {
	Title              string
	Severity           string
	CWE                string
	VerificationMethod string
	CVSSVector         string
	Target             string
	Endpoint           string
	HTTPMethod         string
	Description        string
	Proof              string
}

// VerificationVerdict is the verifier's decision.
//   - Confirmed: independently reproduced → persist as Verified.
//   - Inconclusive: verifier could not reach a verdict (infra error / budget) →
//     persist but flagged Unverified so it is never claimed as validated.
//   - neither (explicit rejection): drop the finding.
type VerificationVerdict struct {
	Confirmed    bool
	Inconclusive bool
	Reason       string
	Evidence     string
}

// FindingVerifier independently re-tests a candidate and returns a verdict.
type FindingVerifier func(VerificationRequest) VerificationVerdict

var (
	// findingVerifiers is keyed by scan-context ID so concurrent scans never
	// cross-wire: scan A's reports are always verified by scan A's agent, not
	// whichever agent was constructed most recently.
	findingVerifiers  = make(map[string]FindingVerifier)
	findingVerifierMu sync.RWMutex
)

// SetFindingVerifier installs a legacy scan-context verifier for callers that
// use Register. Production agents use RegisterWithVerifier so each parallel
// registry owns its callback. Passing nil clears the compatibility entry.
func SetFindingVerifier(contextID string, v FindingVerifier) {
	findingVerifierMu.Lock()
	defer findingVerifierMu.Unlock()
	if v == nil {
		delete(findingVerifiers, contextID)
		return
	}
	findingVerifiers[contextID] = v
}

func getFindingVerifier(contextID string) FindingVerifier {
	findingVerifierMu.RLock()
	defer findingVerifierMu.RUnlock()
	return findingVerifiers[contextID]
}

// ── Per-instance vulnerability stores ──
// Each scan context gets its own vulnerability list.
// The global functions delegate to the active scan context's store.
var (
	stores   = make(map[string]*vulnStore) // scanContextID → store
	storesMu sync.RWMutex
)

// ── Child → parent context mapping ──
// Decouples the reporting package from web/server.go. The web layer calls
// SetParentContext at session start so PromoteToParent / promoteIfChildOfWildcard
// can resolve the parent without importing or knowing about scanSession.
//
// CleanupContext removes both the vuln store AND the child→parent entry,
// so the map does not leak entries across scan lifecycles.
var parentMap = struct {
	sync.RWMutex
	m map[string]string
}{m: make(map[string]string)}

// SetParentContext declares that vulns reported into childCtxID should also
// be promoted into parentCtxID via PromoteToParent. Idempotent: calling twice
// with the same arguments is a no-op. Passing an empty parentCtxID clears
// any prior mapping.
func SetParentContext(childCtxID, parentCtxID string) {
	if childCtxID == "" {
		return
	}
	parentMap.Lock()
	defer parentMap.Unlock()
	if parentCtxID == "" {
		delete(parentMap.m, childCtxID)
		return
	}
	parentMap.m[childCtxID] = parentCtxID
}

// GetParentContext returns the parent context ID registered for childCtxID,
// or the empty string if none is set.
func GetParentContext(childCtxID string) string {
	parentMap.RLock()
	defer parentMap.RUnlock()
	return parentMap.m[childCtxID]
}

// vulnStore is a per-instance vulnerability list.
type vulnStore struct {
	mu    sync.RWMutex
	vulns []Vulnerability
}

// getStoreByID returns the vulnerability store for a specific context ID.
// Creates a new store if one doesn't exist.
func getStoreByID(id string) *vulnStore {
	storesMu.RLock()
	s, ok := stores[id]
	storesMu.RUnlock()
	if ok {
		return s
	}

	// Create store for this context
	storesMu.Lock()
	defer storesMu.Unlock()
	if s, ok := stores[id]; ok {
		return s // double-check after write lock
	}
	s = &vulnStore{}
	stores[id] = s
	return s
}

// getStore returns the vulnerability store for the default scan context.
// Used by backward-compatible global functions (CLI mode).
func getStore() *vulnStore {
	return getStoreByID(scanctx.Default().ID)
}

// getStoreForContext returns the vulnerability store for a specific context ID.
func getStoreForContext(contextID string) *vulnStore {
	storesMu.RLock()
	s, ok := stores[contextID]
	storesMu.RUnlock()
	if ok {
		return s
	}
	storesMu.Lock()
	defer storesMu.Unlock()
	if s, ok := stores[contextID]; ok {
		return s
	}
	s = &vulnStore{}
	stores[contextID] = s
	return s
}

// Register adds reporting tools without an agent-local verifier. It is kept for
// CLI/tests and falls back to the legacy scan-context verifier lookup.
func Register(r *tools.Registry) {
	RegisterWithVerifier(r, nil)
}

// RegisterWithVerifier binds an independent verifier to this exact registry.
// This is required for multi-agent scans: each hunter blocks on and uses its
// own LLM client while validating a report, so parallel agents never borrow a
// busy sibling's verifier or overwrite a process-global callback.
func RegisterWithVerifier(r *tools.Registry, verifier FindingVerifier) {
	r.Register(&tools.Tool{
		Name: "report_vulnerability",
		Description: `Report a VERIFIED, EXPLOITABLE vulnerability with proof. CRITICAL RULES:
1. You MUST have already EXPLOITED this vulnerability before calling this tool.
2. You MUST provide exploitation_proof showing concrete evidence (extracted data, reflected payload, command output, callback, timing proof).
3. Reports without exploitation proof for severity >= medium will be REJECTED — exploit first, then report.
3b. MANDATORY CONTROL/BASELINE TEST for any "bypass", "desync", or "differential" claim: before reporting, prove the behavior does NOT already happen WITHOUT your exploit. Run the baseline and put BOTH results in exploitation_proof. Examples: a Host-header/deployment "bypass" → hit production directly with no Host trick; if the response is identical it is PUBLIC, not a bypass. Request smuggling → resend the two requests with NO CL/TE headers; two responses then = pipelining, not desync. OAuth "state CSRF" → the authorize endpoint echoing state=test is by design (state is client-validated); complete the callback. If baseline == exploit-result, it is a FALSE POSITIVE — do not report.
4. Do NOT report missing headers, version disclosure, or scanner-only findings as vulnerabilities — those are INFO at best.
5. Duplicate checks are scoped to the current scan run only. If the same issue was found in a previous scan and is still exploitable now, report it again for this scan.
6. SEVERITY MUST MATCH CVSS SCORE per HackerOne standards:
   - Critical (9.0-10.0): RCE, full DB dump, mass account takeover, admin access
   - High (7.0-8.9): SQLi with data extraction, stored XSS with session hijack, SSRF to internal services, auth bypass, IDOR exposing PII
   - Medium (4.0-6.9): Reflected XSS, CSRF on non-critical actions, open redirect, info disclosure of internal data
   - Low (0.1-3.9): Clickjacking, missing cookie flags, CORS without credential theft, path disclosure
   - None/Info (0.0): Missing headers, version disclosure, self-XSS, DNS config issues`,
		Parameters: []tools.Parameter{
			{Name: "title", Description: "Vulnerability title", Required: true},
			{Name: "severity", Description: "Severity per HackerOne CVSS ranges: critical (CVSS 9.0-10.0), high (7.0-8.9), medium (4.0-6.9), low (0.1-3.9), info (0.0). Must match your CVSS score. If omitted it is derived from cvss (or defaults to medium) so a real finding is never lost — but always set it explicitly.", Required: false},
			{Name: "description", Description: "Detailed description of the vulnerability. Strongly recommended; if omitted it is synthesized from the title and proof so a real finding is never lost to a missing field.", Required: false},
			{Name: "exploitation_proof", Description: "REQUIRED for medium+. Concrete evidence of exploitation: extracted data, reflected payload text, command output, timing measurement, callback confirmation. Paste actual output here.", Required: false},
			{Name: "verification_method", Description: "How you verified: exploited, time_based, data_extracted, callback_received, error_based, blind_confirmed, reflected, authenticated, manual_verified", Required: false},
			{Name: "oob_token", Description: "For callback-confirmed SSRF: the exact token returned by oob_callback generate. Required so the backend can reject scanner-origin and DNS-only interactions.", Required: false},
			{Name: "impact", Description: "Real-world impact assessment", Required: false},
			{Name: "target", Description: "Target URL/host", Required: false},
			{Name: "endpoint", Description: "Affected endpoint", Required: false},
			{Name: "method", Description: "HTTP method", Required: false},
			{Name: "cve", Description: "CVE identifier if known", Required: false},
			{Name: "cvss", Description: "CVSS 3.1 base score (0.0-10.0). MUST match severity: critical=9.0-10.0, high=7.0-8.9, medium=4.0-6.9, low=0.1-3.9, info=0.0. If omitted, a default is derived from severity.", Required: false},
			{Name: "cvss_vector", Description: "CVSS 3.1 vector string, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. Components: AV(Attack Vector):N/A/L/P, AC(Attack Complexity):L/H, PR(Privileges Required):N/L/H, UI(User Interaction):N/R, S(Scope):U/C, C(Confidentiality):N/L/H, I(Integrity):N/L/H, A(Availability):N/L/H", Required: false},
			{Name: "technical_analysis", Description: "Technical details of the vulnerability", Required: false},
			{Name: "poc_description", Description: "Step-by-step PoC description", Required: false},
			{Name: "poc_script_code", Description: "Reproducible PoC code (curl, python, etc.)", Required: false},
			{Name: "remediation_steps", Description: "Remediation recommendations", Required: false},
			{Name: "fix", Description: "CONCRETE fix — ideally a minimal code/config patch or diff the developer can apply directly (e.g. replace string-concatenated SQL with a parameterized query, add the missing authorization check, HTML-escape the output). Include the file/function when known from source. This is what makes the report actionable.", Required: false},
			{Name: "cwe_id", Description: "CWE identifier if known, e.g. CWE-79 for XSS, CWE-89 for SQLi, CWE-78 for command injection", Required: false},
			{Name: "owasp", Description: "OWASP Top 10 (2021) category if known, e.g. A03 for Injection, A01 for Broken Access Control", Required: false},
			{Name: "hypothesis_id", Description: "Optional ledger hypothesis id this finding proves (e.g. H-3 from record_hypothesis / authz_matrix / verify_xss / verify_oob). On success the finding is linked to that hypothesis and it is marked proven — this satisfies the finish gate without a separate add_hypothesis_evidence call.", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return reportVulnForRegistryWithVerifier(r, verifier, args)
		},
	})
}

func reportVulnForRegistryWithVerifier(reg *tools.Registry, verifier FindingVerifier, args map[string]string) (tools.Result, error) {
	return reportVulnWithContextIDAndVerifier(reg.GetScanContextID(), verifier, args)
}

// reportVuln is the backward-compatible version using scanctx.Default().
//
//lint:ignore U1000 kept as a package-level compatibility wrapper for callers in this package.
func reportVuln(args map[string]string) (tools.Result, error) {
	return reportVulnWithContextID(scanctx.Default().ID, args)
}

func reportVulnWithContextID(contextID string, args map[string]string) (tools.Result, error) {
	return reportVulnWithContextIDAndVerifier(contextID, nil, args)
}

func reportVulnWithContextIDAndVerifier(contextID string, verifier FindingVerifier, args map[string]string) (tools.Result, error) {
	severity := strings.ToLower(strings.TrimSpace(args["severity"]))
	if severity == "" {
		// Salvage a missing severity (a common model omission) instead of
		// bouncing a proven finding: derive it from the CVSS score when given,
		// else default to medium. This never INFLATES severity, and the
		// severity/proof gates below still apply, so an unproven finding is
		// still rejected on its own merits.
		if cv, err := strconv.ParseFloat(strings.TrimSpace(args["cvss"]), 64); err == nil && cv > 0 {
			severity = severityFromCVSS(cv)
		} else {
			severity = "medium"
		}
		args["severity"] = severity
	}
	proof := strings.TrimSpace(args["exploitation_proof"])
	method := strings.ToLower(strings.TrimSpace(args["verification_method"]))
	title := strings.TrimSpace(args["title"])
	target := strings.TrimSpace(args["target"])
	endpoint := strings.TrimSpace(args["endpoint"])
	if target == "" {
		if sc := scanctx.Get(contextID); sc != nil {
			if targets := sc.Targets(); len(targets) == 1 {
				target = targets[0]
				args["target"] = target
			}
		}
	}

	// ── Salvage a missing description ──
	// `description` is no longer a hard-required registry field: models (esp.
	// smaller ones) routinely emit a complete report_vulnerability call with
	// title/severity/proof but drop the prose `description`, which previously
	// bounced the whole finding as "missing required parameter" and LOST a real,
	// proven vulnerability. Synthesize one from the strongest available field so
	// the finding survives; a model-supplied description is always preferred.
	if strings.TrimSpace(args["description"]) == "" {
		var synth []string
		if title != "" {
			synth = append(synth, title)
		}
		for _, k := range []string{"technical_analysis", "impact", "poc_description", "exploitation_proof"} {
			if v := strings.TrimSpace(args[k]); v != "" {
				synth = append(synth, v)
				break
			}
		}
		desc := strings.TrimSpace(strings.Join(synth, "\n\n"))
		if desc == "" {
			desc = title
		}
		args["description"] = desc
	}

	// ── Gate 0: Fast duplicate check before spending effort on report validation ──
	// This is repeated under the write lock just before append to close races.
	store := getStoreByID(contextID)
	store.mu.RLock()
	if existing, msg, ok := findDuplicateVulnerability(store.vulns, title, args["description"], args["cve"], args["cwe_id"], target, endpoint); ok {
		store.mu.RUnlock()
		return duplicateResult(existing, msg), nil
	}
	store.mu.RUnlock()

	// ── Gate 0.5: Reject fabricated / target-unreachable non-findings ──
	// The shape-based gates below only check that a proof is present and
	// well-formed, so two classes of NON-vulnerability slip through as
	// medium+/critical and even reach Telegram/Discord: (1) simulated /
	// placeholder / "workaround to satisfy the engine" findings the agent
	// invents to complete a task, and (2) a target reported as unreachable
	// (host down / unresolvable) dressed up as a vuln. Reject both here,
	// before auto-inference or the expensive verifier run, so the evidence
	// operators receive always reflects a real, reproducible finding.
	if rejection := checkFabricatedFinding(title, endpoint, args["description"], proof, severity); rejection != "" {
		log.Printf("[reporting] fabricated/unreachable gate rejected finding: severity=%s title=%q", severity, title)
		return tools.Result{Output: rejection}, nil
	}

	// ── Auto-inference for missing/incomplete fields ──
	// A prose field is promoted to exploitation_proof ONLY when it itself
	// already contains a concrete exploitation outcome (i.e. the agent pasted
	// real output into the wrong field). Generic prose must never masquerade as
	// proof: doing so silently defeats Gate 2 and yields "evidence" that merely
	// restates the description, so notifications/reports carry no real proof.
	// ── Bridge: fold browser-confirmed XSS proof from the ledger into the proof ──
	// verify_xss records concrete browser-execution proof (a dialog/console/DOM
	// signal carrying the injected nonce) in the shared ledger, but models do not
	// reliably paste that verdict into exploitation_proof — so a genuinely
	// browser-confirmed XSS gets dropped by the reflection-only gate below. When
	// the ledger holds a verify_xss confirmation for this scan, fold it into the
	// proof so the finding is judged on the real evidence, not on what the model
	// happened to paste.
	if reportLooksLikeXSS(title, args["description"], args["cwe_id"]) {
		if bp := ledgerBrowserXSSProof(contextID); bp != "" &&
			!strings.Contains(strings.ToLower(proof), "browser-confirmed xss") {
			proof = strings.TrimSpace(proof + "\n" + bp)
			args["exploitation_proof"] = proof
		}
	}

	// ── Bridge: fold a deterministic verify_* confirmation from the ledger ──
	// The verify_sqli / verify_ssti / verify_xxe / verify_csrf / verify_xss tools
	// record exploit-proven evidence on a baseline-vs-probe differential (only on
	// a positive confirmation). When such a confirmation exists for this
	// finding's class, fold it into the proof and treat the finding as
	// exploit-proven below. Without this, a deterministically confirmed bug is
	// wrongly flagged "needs manual verification" whenever the slower LLM
	// re-verifier cannot independently reproduce it (routinely the case for CSRF
	// and SSTI) — undercutting the very confirmers that produced the proof. A
	// positive DISPROOF from the independent verifier still drops the finding
	// earlier, so this only rescues the inconclusive/absent-verifier case.
	verifierProven := false
	if cls := reportVulnClass(title, args["description"], args["cwe_id"]); cls != "" {
		if vp := ledgerVerifierProof(contextID, cls); vp != "" {
			verifierProven = true
			if !strings.Contains(strings.ToLower(proof), strings.ToLower(vp)) {
				proof = strings.TrimSpace(proof + "\n" + vp)
				args["exploitation_proof"] = proof
			}
		}
	}

	if proof == "" {
		for _, cand := range []string{args["description"], args["technical_analysis"], args["poc_description"]} {
			if c := strings.TrimSpace(cand); len(c) >= 20 && HasConcreteImpact(c) {
				proof = c
				args["exploitation_proof"] = proof
				break
			}
		}
	}
	if severity != "info" && method == "" {
		// Infer verification method from proof or title if evidence is present
		lp := strings.ToLower(proof + " " + title + " " + args["description"])
		switch {
		case strings.Contains(lp, "error") || strings.Contains(lp, "sqlstate") || strings.Contains(lp, "syntax"):
			method = "error_based"
			args["verification_method"] = method
		case strings.Contains(lp, "sleep") || strings.Contains(lp, "delay") || strings.Contains(lp, "time"):
			method = "time_based"
			args["verification_method"] = method
		case strings.Contains(lp, "callback") || strings.Contains(lp, "oob") || strings.Contains(lp, "dns"):
			method = "callback_received"
			args["verification_method"] = method
		case strings.Contains(lp, "uid=") || strings.Contains(lp, "secret"):
			method = "data_extracted"
			args["verification_method"] = method
		case strings.Contains(lp, "reflect") || strings.Contains(lp, "script"):
			method = "reflected"
			args["verification_method"] = method
		}
	}

	// ── Gate 1: Validate verification method ──
	// verification_method is no longer a registry-required param (so the registry
	// doesn't batch-reject before this richer, severity-aware gate runs). A real
	// (non-info) finding must still declare HOW it was verified; info findings are
	// advisory and may omit it. Any method that IS provided must be valid.
	if severity != "info" && method == "" {
		return tools.Result{
			Output: fmt.Sprintf("❌ REJECTED: '%s' reported as %s but has NO verification_method — ⚠️ CRITICAL: You MUST re-call report_vulnerability IMMEDIATELY with 'verification_method' specified (one of: %s) and ALL other required parameters so this finding is saved to the dashboard. If it is not exploitable, downgrade severity to 'info'.",
				title, strings.ToUpper(severity), formatValidMethods()),
		}, nil
	}
	if method != "" && !validVerificationMethods[method] {
		return tools.Result{
			Output: fmt.Sprintf("❌ REJECTED: Invalid verification_method '%s'. Must be one of: %s\n\nYou must EXPLOIT the vulnerability first, then report with the correct verification method.",
				method, formatValidMethods()),
		}, nil
	}

	// ── Gate 2: Require exploitation proof for every real vulnerability ──
	// MAPTA principle: mandatory proof-of-concept for ALL findings. Only 'info'
	// (advisory, non-exploitable) is exempt from the proof + verifier pipeline.
	isHighSeverity := severity == "critical" || severity == "high" || severity == "medium"
	requiresValidation := severity != "" && severity != "info"
	if requiresValidation && (proof == "" || len(proof) < 20) {
		return tools.Result{
			Output: fmt.Sprintf(`❌ REJECTED: '%s' reported as %s but has NO exploitation proof.

XALGORIX RULE: You MUST exploit the vulnerability BEFORE reporting it.

Required steps:
1. You found a potential %s → Good, but not enough to report.
2. Now EXPLOIT it safely — extract data, trigger the payload, confirm the behavior.
3. Paste the ACTUAL OUTPUT of exploitation into 'exploitation_proof'.
4. Then call report_vulnerability again with the proof.

If you cannot exploit it, downgrade severity to 'info' and report as informational.`,
				title, strings.ToUpper(severity), title),
		}, nil
	}

	// ── Gate 2.5: SSRF callback provenance ──
	// Apply this regardless of the declared method whenever the claim uses OOB
	// evidence. In-band internal data extraction remains valid without OOB.
	if isSSRFClaim(title, args["description"], args["cwe_id"]) &&
		usesSSRFOOBEvidence(args["oob_token"], method, proof, args["description"]) {
		if rejection := validateSSRFOOBProof(args["oob_token"], proof); rejection != "" {
			return tools.Result{Output: rejection}, nil
		}
	}

	// ── Gate 3: Check for common false positive patterns ──
	if rejection := checkFalsePositive(title, args["description"], severity, proof); rejection != "" {
		// Audit trail: record what the false-positive gate dropped (and at what
		// severity) so the keyword/PII lists can be reviewed and tuned if a
		// legitimate finding is ever bounced.
		log.Printf("[reporting] false-positive gate rejected finding: severity=%s title=%q", severity, title)
		return tools.Result{Output: rejection}, nil
	}

	// ── Gate 3.5: Claim consistency — does the evidence actually support the
	// claimed CWE / verification_method / CVSS impact? This is a SEMANTIC check
	// (relational) rather than a keyword blocklist, so it generalizes across the
	// many shapes of "mislabeled / inflated" findings.
	if rejection := checkClaimConsistency(title, args["cwe_id"], method, args["cvss_vector"], severity, args["description"], proof); rejection != "" {
		return tools.Result{Output: rejection}, nil
	}

	// ── Gate 4: Smart Deduplication — same vuln type on same endpoint = duplicate ──
	store = getStoreByID(contextID)
	store.mu.RLock()
	if existing, msg, ok := findDuplicateVulnerability(store.vulns, title, args["description"], args["cve"], args["cwe_id"], target, endpoint); ok {
		store.mu.RUnlock()
		return duplicateResult(existing, msg), nil
	}
	store.mu.RUnlock()

	// ── Gate 4.5: Independent verification (always-on for every actionable finding) ──
	// Hand the candidate to the dedicated Verifier agent, which re-tests it
	// from scratch. Explicit rejection → drop. Confirmed → mark Verified.
	// Inconclusive → persist but flagged Unverified (never claimed as validated).
	// No lock is held here: verification is slow (LLM + re-testing).
	verifierConfirmed := false
	verifierInconclusiveKept := false // inconclusive verdict but proof preserved → flagged for manual review
	// The independent Verifier runs for EVERY actionable finding — critical,
	// high, medium AND low. A low-severity claim is still a claim, and "real
	// validation, not just detection" has to hold across the board, so low
	// findings are re-tested too rather than reported on the agent's say-so.
	// Only 'info' (advisory, non-exploitable) is exempt — requiresValidation is
	// false for it — matching the Gate 2 proof requirement.
	if requiresValidation {
		vf := verifier
		if vf == nil {
			vf = getFindingVerifier(contextID)
		}
		if vf != nil {
			verdict := vf(VerificationRequest{
				Title:              title,
				Severity:           severity,
				CWE:                strings.TrimSpace(args["cwe_id"]),
				VerificationMethod: method,
				CVSSVector:         strings.TrimSpace(args["cvss_vector"]),
				Target:             target,
				Endpoint:           endpoint,
				HTTPMethod:         args["method"],
				Description:        args["description"],
				Proof:              proof,
			})
			switch {
			case verdict.Confirmed:
				verifierConfirmed = true
			case verdict.Inconclusive:
				// The verifier did NOT disprove the finding — it simply could not
				// independently reproduce it (it ran out of turn/time budget, hit an
				// LLM error, or the class needs state/timing/OOB it lacks). Dropping
				// here loses REAL bugs (e.g. an RCE whose own proof shows
				// `uid=0(root)`) and buries findings the operator should review. So
				// the finding is ALWAYS preserved and explicitly flagged for manual
				// verification (TagManualReview) rather than discarded as a false
				// positive. Only an explicit "rejected" verdict (positive disproof)
				// drops a finding.
				verifierInconclusiveKept = true
				// fall through to persistence (Verified=false, tagged manual-review)
			default:
				return tools.Result{
					Output: fmt.Sprintf("❌ REJECTED by independent verifier: %s\n\n%s\n\nThe finding could NOT be independently reproduced. Re-test with a control/baseline and only report again if it genuinely holds. If it is by-design or unexploitable, drop it.",
						strings.TrimSpace(verdict.Reason), strings.TrimSpace(verdict.Evidence)),
					Metadata: map[string]any{"verifier_rejected": true},
				}, nil
			}
		}
	}

	// ── Gate 5: Severity classification — enforce max severity per vuln type ──
	originalSeverity := ""
	if cappedSev, reason := classifySeverity(title, args["description"], severity, proof); cappedSev != severity {
		originalSeverity = severity
		severity = cappedSev
		_ = reason // will be included in output message below
	}

	// ── Auto-downgrade: weak proof for high severity ──
	// Drop by one severity level (not nuclear to "info") so CVSS enforcement
	// can still correct it. E.g. high → medium, critical → high.
	if originalSeverity == "" && isHighSeverity && !hasStrongEvidence(severity, proof, args["description"]) {
		originalSeverity = severity
		switch severity {
		case "critical":
			severity = "high"
		case "high":
			severity = "medium"
		case "medium":
			severity = "low"
		default:
			severity = "info"
		}
	}

	var cvss float64
	if c := args["cvss"]; c != "" {
		_, _ = fmt.Sscanf(c, "%f", &cvss)
	}
	cvssVector := strings.TrimSpace(args["cvss_vector"])

	// ── Gate 6: CVSS-to-Severity enforcement (HackerOne standard) ──
	// If CVSS was provided, ensure severity matches the HackerOne CVSS ranges.
	// CVSS is authoritative: Critical=9.0-10.0, High=7.0-8.9, Medium=4.0-6.9, Low=0.1-3.9, None=0.0
	// This gate overrides all prior adjustments — the CVSS score is the source of truth.
	if cvss > 0 {
		cvssSeverity := severityFromCVSS(cvss)
		if severityRank[severity] > severityRank[cvssSeverity] {
			// Severity label is higher than what CVSS justifies → downgrade
			if originalSeverity == "" {
				originalSeverity = severity
			}
			severity = cvssSeverity
		} else if severityRank[severity] < severityRank[cvssSeverity] {
			// Severity label is lower than CVSS justifies → upgrade to match
			if originalSeverity == "" {
				originalSeverity = severity
			}
			severity = cvssSeverity
		}
	}

	// If no CVSS provided, auto-assign a default CVSS based on severity
	if cvss == 0 {
		switch severity {
		case "critical":
			cvss = 9.5
		case "high":
			cvss = 8.0
		case "medium":
			cvss = 5.5
		case "low":
			cvss = 2.5
		default:
			cvss = 0.0
		}
	}

	store = getStoreByID(contextID) // re-resolve in case of race
	store.mu.Lock()
	if existing, msg, ok := findDuplicateVulnerability(store.vulns, title, args["description"], args["cve"], args["cwe_id"], target, endpoint); ok {
		store.mu.Unlock()
		return duplicateResult(existing, msg), nil
	}

	// Does the agent's OWN proof contain a concrete, unambiguous exploitation
	// outcome (command output like `uid=0(root)`, extracted DB rows, an OOB
	// callback hit)? This is the STRICT bar (HasConcreteImpact), not the looser
	// hasStrongEvidence — a stray Set-Cookie can't qualify. A deterministic
	// verify_* confirmation recorded in the ledger (verifierProven) is equally
	// concrete, independent proof, so it also qualifies.
	exploitProven := HasConcreteImpact(proof) || verifierProven

	// Verification tag: every finding carries exactly one, so the UI/report can
	// show its confidence at a glance.
	//   • Independent Verifier reproduced it            → TagVerified.
	//   • Verifier didn't re-confirm, but the finding's OWN proof shows a
	//     concrete exploitation outcome                 → TagExploitProven.
	//     (An RCE whose proof is `uid=0(root)` is proven — not a guess — so it
	//      must NOT be buried under "manual verification needed".)
	//   • Otherwise (no concrete proof yet)             → TagManualReview.
	tags := make([]string, 0, 1)
	switch {
	case verifierConfirmed:
		tags = append(tags, TagVerified)
	case exploitProven:
		tags = append(tags, TagExploitProven)
	default:
		tags = append(tags, TagManualReview)
	}

	// A finding is "validated" (Verified=true, so reports don't stamp it
	// "UNVERIFIED — manual review required") when the independent verifier
	// confirmed it OR its own proof demonstrates concrete exploitation.
	verifiedFlag := verifierConfirmed || exploitProven

	vuln := Vulnerability{
		ID:                 fmt.Sprintf("XALG-%d", len(store.vulns)+1),
		Title:              title,
		Severity:           severity,
		OriginalSeverity:   originalSeverity,
		Description:        args["description"],
		Impact:             args["impact"],
		Target:             target,
		Endpoint:           endpoint,
		Method:             args["method"],
		CVE:                args["cve"],
		CWE:                strings.TrimSpace(args["cwe_id"]),
		OWASP:              strings.TrimSpace(args["owasp"]),
		CVSS:               cvss,
		CVSSVector:         cvssVector,
		TechnicalAnalysis:  args["technical_analysis"],
		PoCDescription:     args["poc_description"],
		PoCScript:          args["poc_script_code"],
		ExploitationProof:  proof,
		VerificationMethod: method,
		Verified:           verifiedFlag,
		Tags:               tags,
		Remediation:        args["remediation_steps"],
		Fix:                strings.TrimSpace(args["fix"]),
		Timestamp:          time.Now().Format(time.RFC3339),
	}

	store.vulns = append(store.vulns, vuln)
	store.mu.Unlock()

	// Panic-safe persistence: if this context is a child of a wildcard parent,
	// promote the vuln into the parent immediately so an agent panic before
	// MergeVulnsToContext at session finalization does not lose it.
	promoteIfChildOfWildcard(contextID, vuln.ID)

	// Close the evidence loop: if the agent named the ledger hypothesis this
	// finding proves, link the finding to it and mark it proven, so the
	// precision finish-gate sees the proven work as reported without requiring
	// a separate add_hypothesis_evidence call. Best-effort; never blocks report.
	ledgerNote := linkFindingToLedger(contextID, vuln.ID, strings.TrimSpace(args["hypothesis_id"]))

	msg := fmt.Sprintf("✅ Vulnerability reported: [%s] %s (%s | CVSS %.1f) — Verified: %v", vuln.ID, vuln.Title, strings.ToUpper(vuln.Severity), vuln.CVSS, vuln.Verified)
	if ledgerNote != "" {
		msg += "\n" + ledgerNote
	}
	if verifierConfirmed {
		msg += "\n✅ Independently CONFIRMED by the verifier."
	} else if exploitProven {
		msg += "\n✅ RECORDED as EXPLOIT-PROVEN: the independent verifier could not re-confirm it within its budget, but your first-party proof shows a concrete exploitation outcome, so it stands as proven (NOT flagged for manual review). Do NOT re-report this — it is already saved."
	} else if verifierInconclusiveKept {
		msg += "\n⚠️ RECORDED as UNVERIFIED (flagged for manual review): the independent verifier could not re-confirm it within its budget, and your proof does not yet show a concrete exploitation outcome, so the finding is preserved rather than dropped. Do NOT re-report this — it is already saved. If you can strengthen the proof (e.g. an OOB callback hit or extracted data), add it via add_note."
	}
	if originalSeverity != "" {
		if cvss > 0 {
			msg += fmt.Sprintf("\n⚠️ SEVERITY ADJUSTED from %s → %s (CVSS %.1f = %s per HackerOne standards)", strings.ToUpper(originalSeverity), strings.ToUpper(severity), cvss, strings.ToUpper(severityFromCVSS(cvss)))
		} else {
			msg += fmt.Sprintf("\n⚠️ SEVERITY ADJUSTED from %s → %s", strings.ToUpper(originalSeverity), strings.ToUpper(severity))
		}
	}

	return tools.Result{
		Output:   msg,
		Metadata: map[string]any{"vuln_id": vuln.ID, "verified": vuln.Verified},
	}, nil
}

// linkFindingToLedger links a persisted finding to the ledger hypothesis it
// proves (when the agent supplied its id) and marks that hypothesis proven.
// This closes the loop the precision finish-gate enforces. It is deterministic
// (the agent names the exact hypothesis id — no fuzzy matching) and best-effort:
// an empty or unknown id is a silent no-op so it can never fail a valid report.
func linkFindingToLedger(contextID, findingID, hypID string) string {
	hypID = strings.TrimSpace(hypID)
	if hypID == "" || contextID == "" {
		return ""
	}
	sc := scanctx.Get(contextID)
	if sc == nil || sc.Ledger == nil {
		return ""
	}
	if _, ok := sc.Ledger.Get(hypID); !ok {
		return "" // unknown id (mistyped/foreign) — do not fabricate a link
	}
	sc.Ledger.AddEvidence(hypID, scanctx.Evidence{
		Kind:      scanctx.EvidenceFindingRef,
		FindingID: findingID,
		Summary:   "Reported as finding " + findingID,
	})
	sc.Ledger.SetStatus(hypID, scanctx.HypothesisProven, "Reported as "+findingID)
	return fmt.Sprintf("🔗 Linked to ledger hypothesis %s (marked proven).", hypID)
}

func duplicateResult(existing Vulnerability, msg string) tools.Result {
	return tools.Result{
		Output: msg,
		Metadata: map[string]any{
			"duplicate":        true,
			"existing_vuln_id": existing.ID,
		},
	}
}

func findDuplicateVulnerability(existing []Vulnerability, title, description, cve, cwe, target, endpoint string) (Vulnerability, string, bool) {
	normalizedTitle := normalizeFindingText(title)
	normalizedTarget := normalizeEndpoint(target)
	// Endpoints use the templated key so object-ID variants of the same path
	// (/orders/1042 vs /orders/2087) are recognized as one finding. Targets are
	// hosts, not object paths, so they keep the plain normalization.
	normalizedEndpoint := dedupEndpointKey(endpoint)
	vulnType := extractVulnTypeWithCWE(title, description, cwe)
	reportedCVEs := findingCVEs(title, description, cve)

	for _, vuln := range existing {
		existingTitle := normalizeFindingText(vuln.Title)
		existingTarget := normalizeEndpoint(vuln.Target)
		existingEndpoint := dedupEndpointKey(vuln.Endpoint)
		existingType := extractVulnTypeWithCWE(vuln.Title, vuln.Description, vuln.CWE)
		sameTarget := normalizedTarget == existingTarget
		if sameTarget && sharesCVE(reportedCVEs, findingCVEs(vuln.Title, vuln.Description, vuln.CVE)) {
			return vuln, fmt.Sprintf("⚠️ DUPLICATE: The same CVE is already reported on target '%s' as %s ('%s'). Skipping the alternate proof endpoint '%s'.", target, vuln.ID, vuln.Title, endpoint), true
		}

		// Exact finding match after trimming/case normalization.
		if sameTarget && normalizedTitle != "" && normalizedTitle == existingTitle && normalizedEndpoint == existingEndpoint {
			return vuln, fmt.Sprintf("⚠️ DUPLICATE: '%s' at endpoint '%s' already reported as %s. Skipping.", title, endpoint, vuln.ID), true
		}

		// Same vulnerability class on the same normalized endpoint.
		if sameTarget && vulnType != "" && vulnType == existingType && normalizedEndpoint != "" && normalizedEndpoint == existingEndpoint {
			return vuln, fmt.Sprintf("⚠️ DUPLICATE: Same vulnerability type '%s' already reported on endpoint '%s' as %s ('%s'). Skipping.\nIf this is genuinely different, use a distinct endpoint or describe how it differs.",
				vulnType, endpoint, vuln.ID, vuln.Title), true
		}
	}

	return Vulnerability{}, "", false
}

func findingCVEs(parts ...string) map[string]struct{} {
	ids := make(map[string]struct{})
	for _, match := range cveIDRe.FindAllString(strings.Join(parts, " "), -1) {
		ids[strings.ToUpper(match)] = struct{}{}
	}
	return ids
}

func sharesCVE(left, right map[string]struct{}) bool {
	for id := range left {
		if _, ok := right[id]; ok {
			return true
		}
	}
	return false
}

func isSSRFClaim(title, description, cwe string) bool {
	combined := strings.ToLower(title + " " + description + " " + cwe)
	return strings.Contains(combined, "ssrf") ||
		strings.Contains(combined, "server-side request forgery") ||
		strings.Contains(combined, "server side request forgery") ||
		strings.Contains(combined, "cwe-918")
}

func usesSSRFOOBEvidence(token, method, proof, description string) bool {
	if strings.TrimSpace(token) != "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "callback_received", "blind_confirmed":
		return true
	}
	combined := strings.ToLower(proof + " " + description)
	return anyContains(combined,
		"callback received", "callback was received", "received callback",
		"callback observed", "observed callback", "http callback",
		"https callback", "oob interaction", "oast interaction",
		"out-of-band", "out of band", "interact.sh", "interactsh",
		"collaborator", "burpcollaborator", "webhook.site", "requestbin",
		"canarytoken", "pingback", "http request received",
		"request received at", "xalgorix-oob-ok", "dns interaction",
		"dns query received")
}

func hasExplicitNoRedirectControl(proof string) bool {
	compact := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(strings.ToLower(proof))
	return anyContains(compact,
		"--max-redirs0", "--max-redirs=0",
		"allow_redirects=false", "follow_redirects=false",
		"max_redirects=0")
}

func isExactOOBToken(token string) bool {
	return token != "" && token == strings.TrimSpace(token) && !strings.ContainsAny(token, "/.: \t\r\n")
}

func validateSSRFOOBProof(token, proof string) string {
	if !isExactOOBToken(token) {
		return "❌ REJECTED (SSRF callback provenance): callback-based SSRF requires the exact bare oob_token returned by oob_callback generate. A URL, hostname, missing token, or free-form callback text is not accepted. Re-test with a fresh token and redirects disabled."
	}
	if !hasExplicitNoRedirectControl(proof) {
		return "❌ REJECTED (SSRF redirect control missing): exploitation_proof must include an explicit technical no-redirect control such as `curl --max-redirs 0`, `allow_redirects=False`, or `follow_redirects=False`. Vague prose about redirects is not sufficient."
	}

	hits := oobsrv.Poll(token)
	nonScannerHTTP := 0
	scannerOriginHTTP := 0
	originUnassessedHTTP := 0
	dnsOnly := 0
	for _, hit := range hits {
		protocol := strings.ToLower(strings.TrimSpace(hit.Protocol))
		switch protocol {
		case "dns":
			dnsOnly++
		case "http", "https":
			switch {
			case !hit.OriginAssessed:
				originUnassessedHTTP++
			case hit.ScannerOrigin:
				scannerOriginHTTP++
			default:
				nonScannerHTTP++
			}
		}
	}
	if nonScannerHTTP > 0 {
		return ""
	}
	if originUnassessedHTTP > 0 {
		return fmt.Sprintf("❌ REJECTED (SSRF origin calibration %s): %d HTTP callback(s) have unassessed origin, alongside %d scanner-origin HTTP and %d DNS-only interaction(s). Remote callbacks must fail closed until external scanner-origin calibration succeeds; poll and report again after calibration, or use returned internal-resource data.",
			oobsrv.ScannerOriginCalibrationState(), originUnassessedHTTP, scannerOriginHTTP, dnsOnly)
	}
	if scannerOriginHTTP > 0 {
		return fmt.Sprintf("❌ REJECTED (scanner-origin SSRF false positive): %d HTTP callback(s) came from Xalgorix's scanner origin; %d DNS-only interaction(s) were also observed. Neither proves that the target server performed SSRF.", scannerOriginHTTP, dnsOnly)
	}
	if dnsOnly > 0 {
		return fmt.Sprintf("❌ REJECTED (DNS-only SSRF evidence): %d DNS interaction(s) were observed, but DNS may originate from the scanner or a recursive resolver. Require an origin-assessed, non-scanner HTTP(S) interaction or returned internal-resource data.", dnsOnly)
	}
	return "❌ REJECTED (SSRF callback not attested): the exact oob_token has no origin-assessed, non-scanner HTTP(S) interaction. Re-test with a fresh token, explicit no-redirect controls, and an uninjected baseline."
}

// anyContains reports whether s contains any of the given substrings.
func anyContains(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// checkClaimConsistency rejects findings whose claimed CWE, verification_method,
// or CVSS impact is not supported by the evidence. Unlike checkFalsePositive
// (a list of known FP shapes), this checks the finding for INTERNAL CONSISTENCY:
// the class must match the mechanism, the method must match the class, and the
// CVSS impact metrics must be backed by proof. This catches mislabeled/inflated
// findings regardless of the specific technology involved.
//
// Only enforced for medium+ (info/low are advisory and don't require proof).
func checkClaimConsistency(title, cwe, method, cvssVector, severity, description, proof string) string {
	sev := strings.ToLower(strings.TrimSpace(severity))
	if sev != "critical" && sev != "high" && sev != "medium" {
		return ""
	}

	proofL := strings.ToLower(proof)
	lp := strings.ToLower(proof + " " + description)
	cweL := strings.ToLower(strings.TrimSpace(cwe))
	vec := strings.ToUpper(cvssVector)
	m := strings.ToLower(strings.TrimSpace(method))

	// Broad "the bug actually did something" markers. Kept intentionally wide so
	// these checks fire ONLY on findings with NO demonstrated outcome — never on
	// a real finding that merely uses different wording. The independent Verifier
	// (not these deterministic gates) is the primary false-positive defense, so
	// these gates are tuned for high precision (few false rejects), low recall.
	hardEvidence := []string{
		"extracted", "extraction", "dumped", "leaked", "exfiltrat", "retrieved", "obtained",
		"callback received", "dns query", "interact.sh", "interactsh", "oast", "collaborator",
		"169.254", "/latest/meta-data", "metadata.google", "internal", "127.0.0.1", "localhost",
		"10.0.0", "192.168", "uid=", "root:", "/etc/passwd", "command execution", "rce", "shell",
		"union select", "information_schema", "@@version", "sqlstate", "syntax error",
		"another user", "other user", "cross-account", "deleted", "modified", "created", "updated",
		"changed", "escalat", "takeover", "session", "token", "credential", "password",
	}

	// 1) verification_method 'reflected' does not prove these classes — but only
	//    reject when the proof ALSO lacks any hard evidence, so a real finding
	//    that merely mislabeled its method is never dropped.
	if m == "reflected" {
		hardClasses := map[string]string{
			"cwe-918": "SSRF", "cwe-78": "OS command injection", "cwe-89": "SQL injection",
			"cwe-639": "IDOR / broken access control", "cwe-287": "authentication bypass",
			"cwe-94": "code injection", "cwe-22": "path traversal",
		}
		if label, ok := hardClasses[cweL]; ok && !anyContains(lp, hardEvidence...) {
			return fmt.Sprintf("❌ REJECTED (claim consistency): verification_method 'reflected' does not prove %s (%s), and the proof shows no extraction/callback/access evidence. Reflection is not exploitation for this class — provide the matching evidence and the correct verification_method.", label, strings.ToUpper(cweL))
		}
	}

	// 2) CVSS High Integrity (I:H) requires evidence of a state change.
	if strings.Contains(vec, "I:H") {
		// Inspect the exploitation proof only. A description commonly explains
		// hypothetical follow-on impact (for example, "the leaked signing key can
		// enable takeover"); that is not evidence that integrity impact was
		// actually demonstrated and must not inflate a read-only primitive.
		if !anyContains(proofL, "deleted", "modified", "created", "updated", "overwrote", "overwritten",
			"changed", "wrote", "inserted", "tampered", "state change", "rce", "command execution",
			"shell", "uid=", "reset", "added", "removed", "poisoned") {
			return "❌ REJECTED (claim consistency): the CVSS vector claims High Integrity impact (I:H) but the proof shows no actual state change. Lower the vector to I:L/I:N or provide integrity-impact evidence."
		}
	}

	// 3) CVSS High Availability (A:H) requires evidence that the primitive can
	//    affect service availability. Arbitrary reads and credential disclosure
	//    do not become critical merely because an agent selects A:H. Proven code
	//    execution is sufficient because it inherently permits stopping or
	//    destroying the affected service; otherwise require a demonstrated crash,
	//    outage, or resource-exhaustion result.
	if strings.Contains(vec, "A:H") {
		if !anyContains(proofL, "rce", "command execution", "remote code execution", "shell", "uid=", "whoami",
			"denial of service", "service unavailable", "service outage", "server crashed", "process crashed",
			"resource exhaustion", "memory exhaustion", "cpu exhaustion", "redos", "timed out for",
			"became unavailable", "stopped responding") {
			return "❌ REJECTED (claim consistency): the CVSS vector claims High Availability impact (A:H) but the proof shows no code execution, crash, outage, or resource exhaustion. Lower the vector to A:L/A:N or provide availability-impact evidence."
		}
	}

	// 4) CVSS High Confidentiality (C:H) requires sensitive data actually obtained.
	//    Command execution / RCE inherently grants confidentiality, so its markers
	//    satisfy this check too (an RCE proof shows `uid=`, not "extracted data").
	//    A proven SQL-injection point ALSO satisfies C:H: a native SQLi signal
	//    (UNION / error-based DBMS error / blind) demonstrates the injection is
	//    exploitable to read arbitrary data, even when the PoC only triggered a
	//    database error rather than dumping rows.
	if strings.Contains(vec, "C:H") {
		sqliClaim := cweL == "cwe-89" || strings.Contains(strings.ToLower(title), "sql injection") ||
			strings.Contains(strings.ToLower(title), "sqli")
		sqliProof := sqliClaim && anyContains(lp, "sql syntax", "you have an error in your sql",
			"syntax error", "sqlstate", "ora-0", "extractvalue", "updatexml", "union select",
			"information_schema", "sqlmap", "unclosed quotation mark", "quoted string not properly")
		if !sqliProof && !anyContains(lp, "extracted", "extraction", "dumped", "leaked", "exfiltrat", "retrieved",
			"read /etc", "/etc/passwd", "password", "credential", "token", "api key", "secret",
			"pii", "ssn", "credit card", "information_schema", "union select", "another user",
			"other user", "private key", "169.254", "/latest/meta-data", "internal", "session",
			"disclosed", "obtained", "accessed",
			"uid=", "root:", "command execution", "rce", "shell", "whoami") {
			return "❌ REJECTED (claim consistency): the CVSS vector claims High Confidentiality impact (C:H) but the proof shows no sensitive data actually obtained. Lower the vector to C:L/C:N or include the obtained data."
		}
	}

	// 5) EVIDENCE PROVENANCE for SQL injection: the proof must show SQLi worked at
	//    the injection point (data via UNION/error/blind-timing, sqlmap, a SQL
	//    error). If the proof shows ONLY command-execution/RCE evidence and NO
	//    SQLi-native evidence, the "SQLi" was likely proven through a different
	//    bug (e.g. an RCE DB dump) — that does not prove SQL injection itself.
	isSQLi := cweL == "cwe-89" || strings.Contains(strings.ToLower(title), "sql injection") ||
		strings.Contains(strings.ToLower(title), "sqli")
	if isSQLi {
		sqliNative := anyContains(lp, "union select", "information_schema", "sqlmap", "sql syntax",
			"syntax error", "sqlstate", "ora-0", "' or 1=1", "' or '1'='1", "sleep(", "pg_sleep",
			"benchmark(", "waitfor delay", "extractvalue", "updatexml", "error-based", "boolean-based",
			"time-based", "differential")
		rceProvenance := anyContains(lp, "rce", "eval(", "exec(", "command injection", "command execution",
			"reverse shell", "web shell", "webshell", "code injection", "via the rce", "using the rce",
			"from the rce", "os command")
		if rceProvenance && !sqliNative {
			return "❌ REJECTED (evidence provenance): the SQL injection proof shows command-execution/RCE evidence but nothing demonstrating SQLi AT THE INJECTION POINT (no UNION/error-based/blind-timing/sqlmap result). Data dumped via a separate RCE does not prove SQL injection. Demonstrate the SQLi directly, or report it as the RCE it actually is."
		}
	}

	// 5) BLIND XXE validation: XXE confirmed only by a generic success message is
	//    not proof. Require retrieved file content or an out-of-band callback.
	isXXE := cweL == "cwe-611" || strings.Contains(strings.ToLower(title), "xxe") ||
		strings.Contains(strings.ToLower(title), "xml external entity")
	if isXXE {
		if !anyContains(lp, "root:", "/etc/passwd", "/etc/", "file://", "<!entity", "<!doctype",
			"callback received", "dns query", "interact.sh", "interactsh", "oast", "collaborator",
			"out-of-band", "retrieved", "exfiltrat", "file content", "169.254", "ssrf via xxe") {
			return "❌ REJECTED (blind validation): the XXE finding shows no retrieved file content and no out-of-band callback — a generic 'success' response does not confirm XXE. Provide /etc/passwd (or other file) contents, or an OOB callback (interactsh/Collaborator), then re-report. If you cannot, report as 'info'."
		}
	}

	return ""
}

// checkFabricatedFinding rejects two classes of non-vulnerability that the
// agent emits when it cannot actually reach or exploit the target yet still
// calls report_vulnerability. They pass the shape-based gates because their
// "proof" is real command output (a ping/curl transcript) or long prose — it
// just is not evidence of a vulnerability — and then surface as critical/high
// noise (including on Telegram/Discord). Matches the substring-gate style of
// checkFalsePositive.
//
//  1. SIMULATED / PLACEHOLDER / WORKAROUND findings — fabricated to "complete
//     the task" (often against invented /placeholder/ endpoints, or with a
//     proof that openly admits it is a stand-in). Never real → rejected at
//     every severity.
//  2. TARGET-UNREACHABLE reported AS a vulnerability — a host that is down or
//     unresolvable is an availability/scope problem, not a finding. Rejected
//     for actionable (non-info) severities, but only when the proof shows NO
//     concrete exploitation outcome, so a genuine finding whose proof merely
//     mentions a timeout in passing is preserved.
func checkFabricatedFinding(title, endpoint, description, proof, severity string) string {
	blob := strings.ToLower(title + " " + endpoint + " " + description + " " + proof)

	// Class 1: explicit fabrication markers — reject at any severity. Keep
	// these markers contextual. A bare word such as "placeholder" is commonly
	// used in legitimate validation prose ("the extracted secret is not a
	// placeholder") and used to suppress a proven Grafana credential leak.
	// Strong phrases and obviously synthetic endpoint/title shapes still catch
	// intentional stand-ins without turning normal English into a veto.
	titleLower := strings.ToLower(strings.TrimSpace(title))
	endpointLower := strings.ToLower(endpoint)
	bodyLower := strings.ToLower(description + " " + proof)
	fabricationMarker := ""
	switch {
	case strings.HasPrefix(titleLower, "simulated "):
		fabricationMarker = "simulated title"
	case strings.HasPrefix(titleLower, "hypothetical "):
		fabricationMarker = "hypothetical title"
	case strings.Contains(titleLower, "simulated finding") || strings.Contains(titleLower, "simulated vulnerability"):
		fabricationMarker = "simulated finding"
	case strings.Contains(endpointLower, "/placeholder/") || strings.HasSuffix(endpointLower, "/placeholder"):
		fabricationMarker = "placeholder endpoint"
	default:
		for _, m := range []string{
			"hypothetical endpoint", "invented endpoint", "simulated endpoint",
			"simulated finding", "simulated vulnerability", "placeholder endpoint",
			"this report is a placeholder", "this finding is a placeholder",
			"workaround to satisfy", "to satisfy the assessment", "assessment engine",
			"task completion requirement", "this report is a workaround",
		} {
			if strings.Contains(bodyLower, m) {
				fabricationMarker = m
				break
			}
		}
	}
	if fabricationMarker != "" {
		return fmt.Sprintf("❌ REJECTED: '%s' is a SIMULATED/PLACEHOLDER/WORKAROUND report (matched %q), not a real vulnerability. Never fabricate a finding to complete a task. If you could not exploit a reachable endpoint, record what you tested with add_note and move on — do NOT call report_vulnerability.", title, fabricationMarker)
	}

	// Class 2: target-unreachable dressed up as an actionable vulnerability.
	// Guarded by HasConcreteImpact so a real finding whose proof also shows a
	// concrete outcome (uid=0, extracted data, an OOB hit) is never dropped.
	if severity != "" && severity != "info" && !HasConcreteImpact(proof) {
		for _, m := range []string{
			"unreachable", "host is down", "host unresponsive",
			"100% packet loss", "could not resolve host", "name or service not known",
			"no route to host", "target host down", "target is down", "assessment blocked",
		} {
			if strings.Contains(blob, m) {
				return fmt.Sprintf("❌ REJECTED: '%s' reports the target as UNREACHABLE (matched %q) — that is an availability/scope issue, not a %s vulnerability. Note it with add_note and finish gracefully; only report an actionable finding backed by a concrete exploitation outcome against a reachable endpoint.", title, m, strings.ToUpper(severity))
			}
		}
	}
	return ""
}

// reportLooksLikeXSS reports whether a finding is an XSS claim, by title/
// description keyword or CWE-79.
func reportLooksLikeXSS(title, description, cwe string) bool {
	lower := strings.ToLower(title + " " + description)
	if strings.Contains(lower, "xss") ||
		strings.Contains(lower, "cross-site script") ||
		strings.Contains(lower, "cross site script") {
		return true
	}
	return strings.Contains(strings.ToLower(cwe), "79")
}

// ledgerBrowserXSSProof returns the browser verifier's confirmation summary for
// a browser-confirmed XSS recorded in this scan's ledger, or "" when none is
// present. verify_xss (internal/tools/browser) records concrete execution proof
// — a dialog/console/DOM signal carrying the injected nonce — as an "exploit"
// evidence on a verify_xss-origin xss hypothesis. That ledger record, not
// whatever the model pasted into exploitation_proof, is the authoritative proof
// that the payload actually RAN, so callers fold it into the reported proof to
// stop the reflection-only false-positive gate from dropping a genuinely
// confirmed XSS.
func ledgerBrowserXSSProof(contextID string) string {
	sc := scanctx.Get(contextID)
	if sc == nil || sc.Ledger == nil {
		return ""
	}
	for _, h := range sc.Ledger.All() {
		if !strings.EqualFold(h.VulnClass, "xss") || !strings.EqualFold(h.Origin, "verify_xss") {
			continue
		}
		for _, ev := range h.Evidence {
			if strings.EqualFold(ev.Kind, "exploit") &&
				strings.Contains(strings.ToLower(ev.Summary), "browser-confirmed xss") {
				return ev.Summary
			}
		}
	}
	return ""
}

// reportVulnClass maps a finding (title/description/CWE) to the canonical
// vuln-class string that the deterministic verifiers record on their ledger
// hypotheses, or "" when the finding is not one of those classes. Used to fold
// a verify_*-confirmed proof into the finding so it is judged on that
// independent evidence.
func reportVulnClass(title, description, cwe string) string {
	lower := strings.ToLower(title + " " + description)
	c := strings.ToLower(cwe)
	switch {
	case strings.Contains(lower, "csrf") || strings.Contains(lower, "cross-site request forgery") ||
		strings.Contains(lower, "cross site request forgery") || strings.Contains(c, "352"):
		return "csrf"
	case strings.Contains(lower, "sql injection") || strings.Contains(lower, "sqli") || strings.Contains(c, "89"):
		return "sqli"
	case strings.Contains(lower, "template injection") || strings.Contains(lower, "ssti") || strings.Contains(c, "1336"):
		return "ssti"
	case strings.Contains(lower, "xxe") || strings.Contains(lower, "xml external entity") || strings.Contains(c, "611"):
		return "xxe"
	case strings.Contains(lower, "xss") || strings.Contains(lower, "cross-site script") ||
		strings.Contains(lower, "cross site script") || strings.Contains(c, "79"):
		return "xss"
	case strings.Contains(lower, "idor") || strings.Contains(lower, "insecure direct object") ||
		strings.Contains(lower, "bola") || strings.Contains(lower, "broken object level") ||
		strings.Contains(lower, "bfla") || strings.Contains(lower, "broken function level") ||
		strings.Contains(lower, "broken access control") ||
		strings.Contains(c, "639") || strings.Contains(c, "862") || strings.Contains(c, "863") ||
		strings.Contains(c, "566") || strings.Contains(c, "285") || strings.Contains(c, "284"):
		return "idor"
	}
	return ""
}

// ledgerVerifierProof returns the confirmation summary recorded by a
// deterministic verify_* tool for a finding of the given class in this scan's
// ledger, or "". The verifiers (verify_sqli / verify_ssti / verify_xxe /
// verify_csrf / verify_xss) record an "exploit" evidence ONLY when they
// positively confirm a vuln via a baseline-vs-probe differential (they return
// early on a non-confirmation, before writing any evidence), so the presence of
// such evidence is authoritative, independent proof of exploitation. This
// generalizes ledgerBrowserXSSProof (which stays for the XSS-specific proof
// fold) to every verifier class, so a deterministically confirmed finding is
// judged exploit-proven instead of being buried under "manual verification
// needed" just because the LLM re-verifier could not reproduce it.
func ledgerVerifierProof(contextID, class string) string {
	if class == "" {
		return ""
	}
	sc := scanctx.Get(contextID)
	if sc == nil || sc.Ledger == nil {
		return ""
	}
	for _, h := range sc.Ledger.All() {
		if !strings.EqualFold(h.VulnClass, class) {
			continue
		}
		// A verify_* tool authored this hypothesis, OR (robust to ledger dedup
		// merging a verifier confirmation onto a pre-existing probe hypothesis,
		// which can retain the probe's origin) an exploit evidence carries a
		// verifier confirmation. Every verifier writes "CONFIRMED"/"confirmed"
		// into its exploit-evidence summary only on a positive differential.
		verifierOrigin := strings.HasPrefix(strings.ToLower(h.Origin), "verify_")
		authzOrigin := strings.EqualFold(h.Origin, "authz_matrix")
		for _, ev := range h.Evidence {
			if !strings.EqualFold(ev.Kind, "exploit") || strings.TrimSpace(ev.Summary) == "" {
				continue
			}
			s := strings.ToLower(ev.Summary)
			switch {
			case verifierOrigin, strings.Contains(s, "confirmed"):
				return ev.Summary
			case authzOrigin && strings.Contains(s, "broken access control"):
				// authz_matrix's HIGH-confidence signal only: a lower identity got
				// the SAME successful response as the authorized baseline (its
				// exploit summary says "broken access control"). Its weaker
				// heuristic ("accessible while the baseline was not successful —
				// verify") is deliberately NOT treated as proof, because that can
				// simply be the other identity's own object.
				return ev.Summary
			}
		}
	}
	return ""
}

func checkFalsePositive(title, description, severity, proof string) string {
	lower := strings.ToLower(title + " " + description)
	isHighSev := severity == "critical" || severity == "high" || severity == "medium"

	// Pattern 1: Missing security headers reported as vulnerability
	headerKeywords := []string{"missing header", "x-frame-options", "x-content-type", "content-security-policy",
		"strict-transport", "x-xss-protection", "referrer-policy", "permissions-policy", "hsts"}
	for _, kw := range headerKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			return fmt.Sprintf("❌ REJECTED: Missing security headers are INFORMATIONAL, not %s. Re-report as severity 'info' if needed.", strings.ToUpper(severity))
		}
	}

	// Pattern 2: Version/technology disclosure
	disclosureKeywords := []string{"version disclosure", "server header", "x-powered-by", "technology disclosure",
		"software version", "banner grabbing"}
	for _, kw := range disclosureKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			return "❌ REJECTED: Version/technology disclosure is INFORMATIONAL unless you can exploit a specific CVE. Provide CVE + exploitation proof, or re-report as 'info'."
		}
	}

	// Pattern 3: Scanner-only findings without manual verification
	scannerKeywords := []string{"nuclei detected", "nuclei found", "scanner reported", "automated scan found",
		"wpscan found", "nmap detected"}
	for _, kw := range scannerKeywords {
		if strings.Contains(lower, kw) && proof == "" {
			return "❌ REJECTED: Scanner-only findings require MANUAL VERIFICATION. Run the scanner, then manually exploit the finding to confirm it. Paste the exploitation output as proof."
		}
	}

	// Pattern 4: CORS without exploitation proof
	if (strings.Contains(lower, "cors") ||
		strings.Contains(lower, "access-control-allow-origin") ||
		strings.Contains(lower, "cross-origin resource sharing")) && isHighSev {
		corsProofKeywords := []string{"cookie", "token", "session", "steal", "extract", "hijack", "javascript", "xmlhttprequest", "fetch("}
		hasExploitProof := false
		lowerProof := strings.ToLower(proof)
		for _, kw := range corsProofKeywords {
			if strings.Contains(lowerProof, kw) {
				hasExploitProof = true
				break
			}
		}
		if !hasExploitProof {
			return "❌ REJECTED: CORS misconfiguration alone is INFORMATIONAL. To report as medium+, you must demonstrate cookie/token theft via CORS (provide PoC JavaScript that exfiltrates data). Otherwise re-report as 'info'."
		}
	}

	// Pattern 5: Open redirect without chaining
	if (strings.Contains(lower, "open redirect") ||
		strings.Contains(lower, "unvalidated redirect") ||
		strings.Contains(lower, "url redirection")) && isHighSev {
		chainKeywords := []string{"oauth", "token", "ssrf", "phishing", "chain", "exfiltrate", "steal"}
		hasChain := false
		lowerProof := strings.ToLower(proof + " " + description)
		for _, kw := range chainKeywords {
			if strings.Contains(lowerProof, kw) {
				hasChain = true
				break
			}
		}
		if !hasChain {
			return "❌ REJECTED: Open redirect alone is INFORMATIONAL. To report as medium+, chain it with OAuth token theft, SSRF, or demonstrate real impact. Otherwise re-report as 'info'."
		}
	}

	// Pattern 6: SSL/TLS *configuration* noise (weak ciphers, old protocol
	// versions, expired/self-signed certs). Scoped to the specific noise
	// patterns so genuine TLS-related exploits — certificate-validation bypass
	// enabling MITM, mTLS auth bypass — are NOT silently dropped just because
	// the title mentions "TLS" or "certificate".
	sslKeywords := []string{
		"weak cipher", "cipher suite", "rc4", "3des",
		"tls 1.0", "tls 1.1", "tlsv1.0", "tlsv1.1", "sslv3", "ssl 3", "ssl 2",
		"sweet32", "poodle", "heartbleed", "beast attack", "crime attack", "logjam", "drown",
		"expired certificate", "certificate expired", "self-signed certificate",
		"self signed certificate", "weak signature algorithm",
	}
	for _, kw := range sslKeywords {
		if strings.Contains(lower, kw) {
			return "❌ REJECTED: SSL/TLS configuration issues (weak ciphers, old protocol versions, expired/self-signed certs) are OUT OF SCOPE. Do not report them. NOTE: a genuine TLS exploit (e.g. certificate-validation bypass enabling MITM) is in scope — title it by its impact, not as a TLS config issue, and include the exploitation proof."
		}
	}

	// Pattern 7: DNS configuration issues (SPF, DMARC, TXT)
	dnsKeywords := []string{"spf", "dmarc", "dkim", "domain-based message authentication", "sender policy framework", "txt record", "email spoofing"}
	for _, kw := range dnsKeywords {
		if strings.Contains(lower, kw) {
			return "❌ REJECTED: DNS and email configuration issues (SPF, DMARC, TXT, DKIM) are OUT OF SCOPE. Do not report them."
		}
	}

	// Pattern 8: CSV injection (almost always Informative on HackerOne)
	csvKeywords := []string{"csv injection", "formula injection", "spreadsheet injection", "csv formula", "dde injection", "excel injection"}
	for _, kw := range csvKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			return "❌ REJECTED: CSV/formula injection is almost always marked INFORMATIVE on HackerOne. It requires victim action (opening file + enabling macros). Re-report as 'low' or 'info' at most."
		}
	}

	// Pattern 9: Clickjacking without exploitation proof
	if strings.Contains(lower, "clickjacking") || strings.Contains(lower, "click jacking") || strings.Contains(lower, "ui redressing") {
		if isHighSev {
			return "❌ REJECTED: Clickjacking is LOW severity (CVSS 2.0-3.9) per HackerOne. To report as medium+, you must demonstrate a sensitive state-changing action that can be performed via the iframe PoC (e.g., delete account, change email). Re-report as 'low'."
		}
	}

	// Pattern 10: Directory listing without sensitive file access
	if strings.Contains(lower, "directory listing") || strings.Contains(lower, "directory index") || strings.Contains(lower, "autoindex") {
		lowerProof := strings.ToLower(proof)
		sensitiveFileEvidence := []string{"password", "credential", "secret", "key", "token", "config", ".env", "database", "backup", ".sql", ".bak"}
		hasSensitive := false
		for _, kw := range sensitiveFileEvidence {
			if strings.Contains(lowerProof, kw) {
				hasSensitive = true
				break
			}
		}
		if !hasSensitive && isHighSev {
			return "❌ REJECTED: Directory listing alone is INFORMATIONAL unless sensitive files (credentials, configs, backups) are exposed AND accessed. Show the actual sensitive file contents in your proof."
		}
	}

	// Pattern 11: TRACE/OPTIONS HTTP method enabled
	traceKeywords := []string{"trace method", "trace enabled", "options method", "http method enabled", "http verb"}
	for _, kw := range traceKeywords {
		if strings.Contains(lower, kw) {
			return "❌ REJECTED: TRACE/OPTIONS methods enabled is INFORMATIONAL. Modern browsers block cross-site TRACE (XST), making this unexploitable. Do not report."
		}
	}

	// Pattern 11a: HTTP request smuggling / desync claimed without a genuine
	// desync proof. The canonical automated false positive: HTTP/1.1
	// PIPELINING (two responses on one connection) plus a redirect engine
	// ECHOING the request path into the Location header, misread as a
	// CL.TE/TE.CL desync + cache poisoning. Real proof is a DIFFERENTIAL — a
	// timing hang vs. an instant baseline, OR a paired follow-up/victim request
	// on a SEPARATE connection that gets corrupted/redirected/delayed or
	// receives the smuggled prefix. "Two responses", a canary reflected in
	// Location, and `x-cache: HIT` on a redirect are NOT proof. Fires only at
	// medium+ and only when the proof shows none of the differential signals,
	// so a genuine desync (which cites timing/victim evidence) passes through.
	smugglingKeywords := []string{
		"request smuggling", "http smuggling", "smuggl", "desync", "desynchron",
		"cl.te", "te.cl", "cl-te", "te-cl", "te.te", "http/1.1 desync", "http desync",
		"request queue poison", "request tunnel", "h2.cl", "h2.te",
	}
	isSmuggling := false
	for _, kw := range smugglingKeywords {
		if strings.Contains(lower, kw) {
			isSmuggling = true
			break
		}
	}
	if isSmuggling && isHighSev {
		lowerProof := strings.ToLower(proof)
		// Specific phrases only — avoid generic tokens like "baseline" or
		// "socket" that appear in canaries/prose and would wave a FP through.
		desyncSignals := []string{
			// (a) timing differential — a hang vs. an instant baseline
			"time-based", "time based", "timing differential", "hang", "hung",
			"delayed", "timed out", "time out", "sleep(", "pg_sleep", "waitfor delay",
			"returned instantly", "instant baseline", "vs baseline", "vs instant",
			"response time delta", "second delay", "seconds delay",
			// (b) cross-connection / victim contamination
			"victim", "another connection", "different connection", "separate connection",
			"second connection", "cross-connection", "socket reuse", "socket-reuse",
			"another socket", "victim socket", "unrelated request", "another user",
			// (c) the follow-up request itself being corrupted by the prefix
			"poisoned the next", "poisoned the following", "next request received",
			"next request returned", "follow-up request", "corrupted the next",
			"405 on the follow", "400 on the follow", "queue poison", "prefix landed on",
		}
		hasDesyncProof := false
		for _, kw := range desyncSignals {
			if strings.Contains(lowerProof, kw) {
				hasDesyncProof = true
				break
			}
		}
		if !hasDesyncProof {
			return "❌ REJECTED: HTTP request smuggling / desync needs a DIFFERENTIAL proof, not a single response. Two responses on one connection is HTTP/1.1 PIPELINING, and a canary reflected in the Location header is just the redirect engine echoing the path — neither proves a desync, and `x-cache: HIT` on a redirect is normal. Prove it with EITHER (a) a time-delay probe (incomplete chunk / bad length) that hangs ~5-10s versus an instant baseline — run the baseline too — OR (b) a paired follow-up/victim request on a SEPARATE connection that gets corrupted, redirected, delayed, or receives your smuggled prefix. First run the two mandatory controls: (1) pipelining control — send the same two requests with NO Content-Length/Transfer-Encoding smuggling headers; if you STILL get two responses it is pipelining, not smuggling; (2) redirect-echo control — send a single benign GET /<canary>; if the canary appears in Location, reflection proves nothing. If neither differential holds, this is a false positive — do not report it (downgrade to 'info' only if there is a real, distinct issue)."
		}
	}

	// Pattern 11a-2: OAuth "state" CSRF claimed from the AUTHORIZATION endpoint
	// alone. The OAuth `state` parameter is generated and validated by the
	// CLIENT application (relying party), NOT by the authorization server
	// (RFC 6749 §10.12). Every authorize endpoint — Microsoft, Google, Okta —
	// accepts and echoes ANY state (state=test, garbage, empty) by design and
	// returns 200; that proves nothing. A real state-CSRF requires completing
	// the full redirect callback and showing the CLIENT app accepts a state it
	// never issued (forced login / account linking with a usable session). Fire
	// at medium+ only when there is no callback/session evidence.
	//
	// This is specifically about the OAuth `state` parameter, so it REQUIRES an
	// OAuth/authorization context. A plain CSRF on a state-CHANGING action is the
	// ordinary way to describe any CSRF — and is exactly what verify_csrf's own
	// proof summary says ("accepted a state-changing POST …") — so "csrf" + the
	// word "state" alone must NOT trip this gate, or a genuine, deterministically
	// confirmed CSRF would be dropped before it is ever reported.
	oauthCtx := strings.Contains(lower, "oauth") ||
		strings.Contains(lower, "openid") ||
		strings.Contains(lower, "/authorize") ||
		strings.Contains(lower, "authorize endpoint") ||
		strings.Contains(lower, "authorization server") ||
		strings.Contains(lower, "/oauth2/") ||
		strings.Contains(lower, "single sign-on") ||
		strings.Contains(lower, "sso")
	isStateCSRF := strings.Contains(lower, "state parameter") ||
		strings.Contains(lower, "missing state validation") ||
		strings.Contains(lower, "state validation") ||
		(oauthCtx && strings.Contains(lower, "state"))
	if isStateCSRF && isHighSev {
		lowerProof := strings.ToLower(proof + " " + description)
		// Evidence that the CLIENT app (not just the authorize endpoint)
		// actually accepted an unissued state / that a session was forced.
		callbackProof := []string{
			"callback", "?code=", "&code=", "code= ", "authorization code",
			"obtained a token", "usable token", "access token returned", "id_token returned",
			"logged into", "logged in as", "authenticated session", "session fixated",
			"account link", "account takeover", "forced login", "victim's account",
			"my listener", "my server received", "exchanged the code",
			"relying party accepted", "app accepted", "unissued state",
		}
		hasCallbackProof := false
		for _, kw := range callbackProof {
			if strings.Contains(lowerProof, kw) {
				hasCallbackProof = true
				break
			}
		}
		if !hasCallbackProof {
			return "❌ REJECTED: OAuth `state` is validated by the CLIENT application, NOT the authorization server (RFC 6749 §10.12). The authorize endpoint accepting/echoing `state=test` (or any value) and returning 200 is BY DESIGN and proves nothing — every Microsoft/Google/Okta authorize endpoint does this. To report a real state-CSRF you must complete the full redirect callback and show the CLIENT app at the redirect_uri accepts a state it never issued, yielding a forced login / account-linking with a usable session. Without that end-to-end proof this is a false positive — do not report (downgrade to 'info' only if there is a distinct, real issue)."
		}
	}

	// Pattern 11a-3: Public OAuth/OIDC identifiers reported as "secret" /
	// "disclosure". The Azure AD tenant ID/UUID, the OAuth `client_id`, the
	// `/.well-known/openid-configuration` document, and tenant branding
	// (display name/logo) are PUBLIC BY DESIGN — they are sent in the clear in
	// every authorization URL and discovery document and are required for
	// federated login. They are not secrets. Only a real credential
	// (client_secret, private/signing key, refresh/access token, password)
	// makes this reportable.
	oauthPublicIDKeywords := []string{
		"client_id", "client id", "tenant id", "tenant uuid", "tenant identifier",
		"azure ad tenant", "azure tenant", "openid-configuration", "openid configuration",
		".well-known/openid", "tenant branding", "oauth metadata", "oidc metadata",
		"issuer disclosure", "authorization server metadata",
	}
	isOAuthPublicID := false
	for _, kw := range oauthPublicIDKeywords {
		if strings.Contains(lower, kw) {
			isOAuthPublicID = true
			break
		}
	}
	if isOAuthPublicID &&
		(strings.Contains(lower, "disclos") || strings.Contains(lower, "expos") ||
			strings.Contains(lower, "leak") || strings.Contains(lower, "secret") ||
			strings.Contains(lower, "sensitive") || strings.Contains(lower, "information disclosure")) {
		lowerProof := strings.ToLower(proof + " " + description)
		realSecret := []string{
			"client_secret", "client secret", "private key", "signing key",
			"refresh_token", "refresh token", "access_token", "bearer ey",
			"password", "api_key", "api key", "-----begin",
		}
		hasRealSecret := false
		for _, kw := range realSecret {
			if strings.Contains(lowerProof, kw) {
				hasRealSecret = true
				break
			}
		}
		if !hasRealSecret {
			return "❌ REJECTED: OAuth/OIDC public identifiers — the Azure AD tenant ID/UUID, the `client_id`, the `/.well-known/openid-configuration` document, tenant branding (display name/logo) — are PUBLIC BY DESIGN (RFC 6749 §2.2; the tenant ID is in every discovery document). They are sent in the clear in every authorization URL and are not secrets. This is not a vulnerability. Only a genuine credential leak — client_secret, private/signing key, a live refresh/access token, or a password — is reportable; include the actual secret value as proof. Otherwise do not report."
		}
	}

	// Pattern 11a-4: Host-header / deployment-protection "bypass" that only
	// reaches PUBLIC content. Sending `Host: prod.example.com` to a staging
	// alias (Vercel/Netlify/etc.) commonly returns 200 — but that is because
	// the platform routes the request to the PRODUCTION alias, which is
	// intentionally public. You did not bypass anything; you asked for the
	// public site and got it. A real bypass must reach content that is NOT
	// available by hitting production directly (staging-only code/config/data,
	// a debug endpoint, an internal backend). The mandatory control is: repeat
	// the request directly against production with NO Host trick — if the
	// response is identical, it is a false positive by construction. Fire at
	// medium+ only when the proof shows no such differential/control.
	isHostBypass := (strings.Contains(lower, "host header") && strings.Contains(lower, "bypass")) ||
		strings.Contains(lower, "deployment protection") ||
		(strings.Contains(lower, "vercel") && (strings.Contains(lower, "bypass") || strings.Contains(lower, "protection"))) ||
		((strings.Contains(lower, "staging") || strings.Contains(lower, "password protection") || strings.Contains(lower, "password-protected")) && strings.Contains(lower, "bypass")) ||
		(strings.Contains(lower, "401") && strings.Contains(lower, "200") && strings.Contains(lower, "host"))
	if isHostBypass && isHighSev {
		lowerProof := strings.ToLower(proof + " " + description)
		// Evidence that the bypass reaches something NOT public on production.
		differentialSignals := []string{
			"production directly", "prod directly", "direct to production", "directly against production",
			"without the host", "without the bypass", "without host override", "no host override",
			"control request", "baseline request", "differs from production", "differs from prod",
			"not available on production", "not public on production", "staging-only", "staging only",
			"only reachable via", "only accessible via the host", "prod returns 401", "prod returns 403",
			"prod returns 404", "production returns 401", "production returns 403", "production returns 404",
			"different content", "differs staging", "staging-specific", "debug endpoint not on prod",
		}
		hasDifferential := false
		for _, kw := range differentialSignals {
			if strings.Contains(lowerProof, kw) {
				hasDifferential = true
				break
			}
		}
		if !hasDifferential {
			return "❌ REJECTED: A Host-header / deployment-protection 'bypass' that returns 200 usually just reached PUBLIC production. Staging and production are commonly two aliases of the SAME deployment (Vercel/Netlify): sending `Host: prod-domain` routes you to the production alias, which is intentionally public — that is not a bypass. MANDATORY control: repeat the exact request DIRECTLY against production with NO Host trick. If the direct-to-production response is identical (same status/body/cookies), this is a false positive by construction — do not report. To be a real finding you must reach content that is NOT available on production directly: a staging-only endpoint/config/env, a debug route, or an internal backend the public site does not expose — show the production-direct control returning 401/403/404 alongside the bypass returning 200 with distinct content. Note: a constant anonymous guest token (e.g. a Salesforce Commerce guest EUID) and public OAuth client_id/redirect_uri are normal public-store behavior, not credentials."
		}
	}

	// Pattern 11b: Username / account / email enumeration. On its own this is
	// NOT a vulnerability — it only matters if it discloses PII/sensitive
	// personal data or is chained into a concrete attack (e.g. account
	// takeover). Differential login/error/timing responses that merely reveal
	// whether an account exists are informational. Reject at medium+ unless the
	// proof shows real PII exposure or a working chain.
	// NOTE: the "...respons" entries are intentionally truncated so the
	// substring match catches both "response" and "responses" (and "responded").
	enumKeywords := []string{
		"username enumeration", "user enumeration", "account enumeration", "email enumeration",
		"username disclosure", "account disclosure", "user existence", "account existence",
		"valid username", "valid account", "enumerate user", "enumerate account",
		"differential auth respons", "differential authentication respons",
		"differential error respons", "observable response discrepancy", "user id enumeration",
	}
	isEnum := false
	for _, kw := range enumKeywords {
		if strings.Contains(lower, kw) {
			isEnum = true
			break
		}
	}
	if isEnum && isHighSev {
		lowerProof := strings.ToLower(proof + " " + description)
		// Elevated only when it actually exposes PII/sensitive personal data or
		// is chained into credential/session compromise — not merely "the
		// account exists".
		// Substring matches (already lower-cased). Deliberately covers common
		// spellings/obfuscations so a genuine PII-leaking finding isn't wrongly
		// bounced, while avoiding over-generic single words ("phone", "address",
		// "name") that would let plain enumeration through.
		piiEvidence := []string{
			// Government / financial identifiers
			"ssn", "social security", "credit card", "creditcard", "credit-card",
			"card number", "cardholder", "cvv", "date of birth", "dob", "passport",
			"driver's license", "drivers license", "driver license", "national id",
			"tax id", "tax number",
			// Contact / location PII (qualified forms only)
			"home address", "billing address", "mailing address", "street address",
			"phone number", "mobile number", "postal code", "zip code",
			// Health / generic PII labels
			"medical record", "health record", "leaked pii", "personal data",
			"personally identifiable", "pii exposed", "full name and",
			// Secrets / auth material that make it a real compromise
			"password", "passwd", "pwd:", "credential", "api key", "api_key", "apikey",
			"access token", "session token", "session id", "bearer token", "private key",
			"account takeover", "reset another", "hijack",
			// MFA / recovery material — exposure enables account takeover.
			"mfa", "2fa", "totp", "otp code", "one-time code", "one time code",
			"security question", "secret question", "secret answer", "recovery code",
			"backup code",
		}
		// NOTE (intentional): this is a noise-triage heuristic, not a security
		// boundary. It only decides whether an ENUMERATION finding may claim
		// medium+; a rejection is non-destructive — the agent is told to prove
		// PII/chained impact or re-report as 'info'. The list covers the common
		// PII/secret terms; it is deliberately NOT exhaustive, and we don't chase
		// every synonym (a borderline finding simply lands as 'info', which is
		// the correct default for bare enumeration).
		hasPII := false
		for _, kw := range piiEvidence {
			if strings.Contains(lowerProof, kw) {
				hasPII = true
				break
			}
		}
		if !hasPII {
			return "❌ REJECTED: Username/account enumeration is NOT a vulnerability on its own — it is INFORMATIONAL. Differential login/error/timing responses that only reveal whether an account exists do not qualify as medium+. To report higher, prove actual PII/sensitive-data disclosure or a concrete chained exploit (e.g. account takeover). Otherwise re-report as 'info'."
		}
	}

	// Pattern 11c: Host header injection / Host header poisoning. Reflecting the
	// Host header (into a link, redirect, or absolute URL) is NOT a
	// vulnerability on its own — it only matters with demonstrated impact:
	// web-cache poisoning, password-reset-link poisoning, routing to an
	// attacker-controlled host, or SSRF. Unlike the medium+ gates, this is
	// enforced at low+ too (bare Host-header reflection is INFO, not even LOW).
	isHostHeader := strings.Contains(lower, "host header injection") ||
		strings.Contains(lower, "host header poison") ||
		strings.Contains(lower, "host header attack") ||
		(strings.Contains(lower, "host header") &&
			(strings.Contains(lower, "inject") || strings.Contains(lower, "poison") ||
				strings.Contains(lower, "spoof") || strings.Contains(lower, "override")))
	if isHostHeader {
		sev := strings.ToLower(strings.TrimSpace(severity))
		if sev != "" && sev != "info" && sev != "informational" {
			lowerProof := strings.ToLower(proof + " " + description)
			impactKeywords := []string{
				"cache poison", "web cache", "cache key", "poisoned response",
				"password reset", "reset link", "reset token", "reset email",
				"account takeover", "ato", "ssrf", "169.254", "metadata endpoint",
				"internal host", "attacker-controlled host", "attacker controlled host",
				"received the request", "oob", "interactsh", "collaborator", "out-of-band",
			}
			hasImpact := false
			for _, kw := range impactKeywords {
				if strings.Contains(lowerProof, kw) {
					hasImpact = true
					break
				}
			}
			if !hasImpact {
				return "❌ REJECTED: Host header injection with no demonstrated impact is INFORMATIONAL — reflecting/overriding the Host header is not a vulnerability by itself. To report as low+, prove concrete impact: web-cache poisoning, password-reset-link poisoning, routing to an attacker-controlled host (with an OOB callback), or SSRF — and include the evidence. Otherwise re-report as 'info'."
			}
		}
	}

	// Pattern 12: Analytics API writeKey "bypass" — these are public client-side tokens by design
	analyticsKeywords := []string{"writekey", "write_key", "write key", "analytics key", "segment key", "analytics api"}
	analyticsEndpoints := []string{"/v1/i", "/v1/t", "/v1/p", "/v1/batch", "/v1/identify", "/v1/track", "/v1/page", "/v1/screen", "/v1/group", "/v1/alias"}
	isAnalyticsFP := false
	for _, kw := range analyticsKeywords {
		if strings.Contains(lower, kw) {
			isAnalyticsFP = true
			break
		}
	}
	if !isAnalyticsFP {
		for _, ep := range analyticsEndpoints {
			if strings.Contains(lower, ep) {
				isAnalyticsFP = true
				break
			}
		}
	}
	if isAnalyticsFP && (strings.Contains(lower, "analytics") || strings.Contains(lower, "validation") || strings.Contains(lower, "writekey") || strings.Contains(lower, "write_key") || strings.Contains(lower, "write key")) {
		return "❌ REJECTED: Analytics API writeKey bypass is NOT a vulnerability. writeKeys are PUBLIC client-side tokens shipped in JavaScript (Segment, Amplitude, Mixpanel, etc.). They are designed to be exposed. Bug bounty programs mark this as N/A or Informational. Do not report."
	}

	// Pattern 13: Rate limiting / brute force — informational EXCEPT on sensitive endpoints
	rateLimitKeywords := []string{"rate limit", "rate-limit", "no rate limit", "brute force", "brute-force",
		"account lockout", "missing rate limit", "unlimited requests", "no lockout", "login throttling"}
	for _, kw := range rateLimitKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			// Exception: rate limiting on sensitive/auth endpoints is a real vuln
			if !isSensitiveEndpointContext(lower, strings.ToLower(proof)) {
				return "❌ REJECTED: Missing rate limiting / brute force is INFORMATIONAL on most endpoints. Re-report as 'info' — unless this is on a sensitive endpoint (login, password reset, OTP, 2FA, signup). If so, mention the sensitive endpoint clearly in the title/description."
			}
		}
	}

	// Pattern 14: Success response without actual impact — APIs returning success:true
	if strings.Contains(lower, "success") && strings.Contains(lower, "true") &&
		(strings.Contains(lower, "any value") || strings.Contains(lower, "arbitrary") || strings.Contains(lower, "without validation")) {
		// Check if proof shows actual data modification or access
		lowerProof := strings.ToLower(proof)
		hasRealImpact := false
		impactWords := []string{"admin access", "modified", "deleted", "created user", "escalat", "bypass", "account", "password", "database"}
		for _, iw := range impactWords {
			if strings.Contains(lowerProof, iw) {
				hasRealImpact = true
				break
			}
		}
		if !hasRealImpact && isHighSev {
			return "❌ REJECTED: API returning success:true without input validation is NOT automatically a vulnerability. You must demonstrate ACTUAL IMPACT — data was modified, accounts were affected, or access was gained. A success response alone proves nothing. Re-report as 'info' with real impact proof, or move on."
		}
	}

	// Pattern 15: Client-side JavaScript config disclosure — PUBLIC_ENV, Sentry DSN, etc.
	// These are intentionally public client-side configurations, not secrets.
	jsConfigKeywords := []string{"sentry dsn", "public_env", "publicenv", "public env",
		"client-side javascript", "client side javascript", "javascript source",
		"next_public_", "react_app_", "vite_", "nuxt_public_",
		"window.__singletons", "window.__next", "window.__nuxt",
		"bundled javascript", "js chunk", "js bundle", "webpack chunk",
		"/_next/static", "/_nuxt/", "/static/js/",
		"application version", "app version"}
	jsConfigHits := 0
	for _, kw := range jsConfigKeywords {
		if strings.Contains(lower, kw) {
			jsConfigHits++
		}
	}
	// If 2+ JS config keywords match AND the "proof" is just viewing source/devtools
	if jsConfigHits >= 2 && isHighSev {
		lowerProof := strings.ToLower(proof)
		realExploitKeywords := []string{"rce", "shell", "admin access", "account takeover", "database",
			"password", "credential", "private key", "secret key", "aws_secret", "payment", "credit card"}
		hasRealExploit := false
		for _, ek := range realExploitKeywords {
			if strings.Contains(lowerProof, ek) {
				hasRealExploit = true
				break
			}
		}
		if !hasRealExploit {
			return "❌ REJECTED: Client-side JavaScript configuration (Sentry DSN, PUBLIC_ENV, API endpoints, app version) is NOT a vulnerability. These are PUBLIC client-side values shipped intentionally in JS bundles. Sentry DSNs are public by design. NEXT_PUBLIC_* vars are meant to be public. Bug bounty programs mark this as Informational or N/A. Do not report."
		}
	}

	// Pattern 16: Sentry DSN specifically — always public, never a vuln
	if strings.Contains(lower, "sentry") && (strings.Contains(lower, "dsn") || strings.Contains(lower, "ingest.sentry.io")) {
		return "❌ REJECTED: Sentry DSN is a PUBLIC client-side key designed to be embedded in JavaScript. It only allows sending error reports — no read access, no data extraction. This is NOT a vulnerability. Do not report."
	}

	// Pattern 17: Generic "information found in JavaScript source" without real impact
	if (strings.Contains(lower, "javascript") || strings.Contains(lower, "js source") || strings.Contains(lower, "source code")) &&
		(strings.Contains(lower, "information disclosure") || strings.Contains(lower, "sensitive information") || strings.Contains(lower, "exposed in")) {
		lowerProof := strings.ToLower(proof)
		// Only reject if proof is just "view source" style — not actual secret leakage
		if !strings.Contains(lowerProof, "password") && !strings.Contains(lowerProof, "private key") &&
			!strings.Contains(lowerProof, "aws_secret") && !strings.Contains(lowerProof, "database_url") &&
			isHighSev {
			return "❌ REJECTED: Finding configuration in client-side JavaScript is expected behavior — frontend apps MUST include API endpoints, service URLs, and public keys to function. This is only a vulnerability if ACTUAL SECRETS (passwords, private keys, database credentials) are exposed. Sentry DSNs, API base URLs, and app versions are NOT secrets."
		}
	}

	// Pattern 18: XSS reported on reflection alone (no proof of execution).
	// Reflection ≠ XSS. The most common XSS false positive is a payload that is
	// merely echoed back — while HTML-encoded, returned with a non-HTML content
	// type, sitting in a non-executing context, or blocked by CSP. Require
	// evidence the script actually RAN (or an out-of-band callback for
	// blind/stored XSS) before allowing medium+.
	isXSS := strings.Contains(lower, "xss") ||
		strings.Contains(lower, "cross-site script") ||
		strings.Contains(lower, "cross site script")
	if isXSS && isHighSev {
		lowerProof := strings.ToLower(proof)

		// Evidence that the payload actually executed or fired out-of-band.
		executionMarkers := []string{
			"execute_js", "executed", "alert fired", "alert(document", "document.domain",
			"document.cookie", "popup", "dialog box", "screenshot", "rendered as html",
			"callback", "xss hunter", "xsshunter", "interact.sh", "interactsh", "oast",
			"collaborator", "dns query", "out-of-band", "out of band", "fired in", "fires in",
			"popped", "script ran", "js ran", "javascript ran", "confirmed execution",
			"executed in the browser", "stole the cookie", "cookie was stolen", "cookie exfiltrated",
			"session hijack", "ran in the victim",
			// Tokens emitted ONLY by the browser XSS verifier (verify_xss /
			// finalizeXSSVerdict) on a real nonce match — i.e. concrete
			// browser-confirmed execution. Without these, the verifier's own
			// confirmation string ("Browser-confirmed XSS: a dialog:alert dialog
			// carrying the nonce … fired while loading …") matched none of the
			// phrases above and, because the pasted payload contains <script>/
			// onerror=, was wrongly dropped here as reflection-only. A spoofed
			// token still faces the independent verifier (Gate 4.5) downstream.
			"browser-confirmed xss", "carrying the nonce", "fired while loading",
			"dialog:alert", "dialog:confirm", "dialog:prompt", "dialog:beforeunload",
			"console:", "dom:marker",
		}
		hasExecution := false
		for _, m := range executionMarkers {
			if strings.Contains(lowerProof, m) {
				hasExecution = true
				break
			}
		}

		if !hasExecution {
			// Encoded reflection in the proof = output encoding is working = NOT XSS.
			encodedMarkers := []string{"&lt;script", "&lt;svg", "&lt;img", "&gt;", "&#x3c;", "&#60;"}
			for _, m := range encodedMarkers {
				if strings.Contains(lowerProof, m) {
					return "❌ REJECTED: The payload appears HTML-ENCODED in your proof (e.g. &lt;script&gt;), which means output encoding is working and the script does NOT execute. Encoded reflection is NOT XSS. Re-test the output context and only report if the payload is reflected RAW and actually executes."
				}
			}

			// Proof that is only the reflected payload (no execution evidence) is
			// the classic false positive.
			looksLikeReflectionOnly := strings.Contains(lowerProof, "<script") ||
				strings.Contains(lowerProof, "onerror=") ||
				strings.Contains(lowerProof, "onload=") ||
				strings.Contains(lowerProof, "<svg") ||
				strings.Contains(lowerProof, "<img")
			if looksLikeReflectionOnly {
				return "❌ REJECTED: XSS proof shows REFLECTION only, not EXECUTION. A payload echoed in the response is not enough — it may land in a non-HTML content type, in a non-executing context, or behind a CSP, or be self-XSS only. Confirm the script actually runs (browser_action execute_js showing alert(document.domain), a screenshot of the dialog, or an out-of-band callback for blind/stored XSS), then re-report. If you cannot prove execution, report as 'info'."
			}
		}
	}

	// Pattern 19: S3/CloudFront subdomain takeover claimed without a claimable origin.
	// The classic false positive: a subdomain CNAMEs to a CloudFront distribution,
	// the global S3 namespace lookup (<name>.s3.amazonaws.com) returns NoSuchBucket,
	// and the agent concludes "takeover" — but the CloudFront origin bucket actually
	// EXISTS (the distribution returns NoSuchKey, not NoSuchBucket). NoSuchKey means
	// no object at that key, not a claimable bucket. Common for MTA-STS endpoints.
	isTakeover := strings.Contains(lower, "subdomain takeover") ||
		strings.Contains(lower, "dangling") ||
		(strings.Contains(lower, "takeover") &&
			(strings.Contains(lower, "subdomain") || strings.Contains(lower, "cname")))
	if isTakeover && isHighSev {
		combined := lower + " " + strings.ToLower(proof)
		involvesS3 := strings.Contains(combined, "s3") ||
			strings.Contains(combined, "cloudfront") ||
			strings.Contains(combined, "nosuchbucket") ||
			strings.Contains(combined, "nosuchkey")
		if involvesS3 {
			// NoSuchKey anywhere in the evidence = the S3 origin bucket EXISTS = not claimable.
			if strings.Contains(combined, "nosuchkey") {
				return "❌ REJECTED: The evidence contains a 'NoSuchKey' response, which means the S3 origin bucket EXISTS (it just has no object at that path). NoSuchKey is NOT NoSuchBucket — the bucket is not claimable, so this is not a subdomain takeover. This is the normal response for a CloudFront-fronted S3 origin and for MTA-STS endpoints. Mark as info / false positive."
			}

			// Evidence that the resource was actually claimed and content served.
			claimMarkers := []string{
				"claimed", "canary", "took over", "taken over", "served my",
				"poc page served", "my content is served", "content is now served",
				"created the bucket and", "registered the", "now serving",
			}
			hasClaimProof := false
			for _, m := range claimMarkers {
				if strings.Contains(strings.ToLower(proof), m) {
					hasClaimProof = true
					break
				}
			}

			// CloudFront-fronted S3: a NoSuchBucket on the global S3 namespace does
			// NOT prove the CloudFront origin is claimable (origins are account-bound,
			// often via OAC/OAI). Require a real claim + canary before allowing this.
			if strings.Contains(combined, "cloudfront") && !hasClaimProof {
				return "❌ REJECTED: A CloudFront-fronted S3 origin cannot be taken over by creating the bucket name in your own AWS account — CloudFront origins are bound to a specific bucket/account. A 'NoSuchBucket' on the global S3 namespace (<name>.s3.amazonaws.com) is NOT the same as the CloudFront origin being claimable. Fetch the CloudFront distribution directly: if it returns NoSuchKey the origin exists and is safe. Only report if you actually claim the resource and serve a benign canary over the real subdomain. Otherwise mark as info."
			}
		}
	}

	// Pattern 20: Time-based SQLi "confirmed" by a single delayed response.
	// A lone slow request is the most common SQLi false positive — network
	// jitter, rate-limiting, or the payload never executing all look identical.
	// Require either hard confirmation (data extraction / DB error) or a
	// DIFFERENTIAL timing comparison (baseline / SLEEP(0) vs SLEEP(N)).
	isSQLi := strings.Contains(lower, "sql injection") ||
		strings.Contains(lower, "sqli") ||
		strings.Contains(lower, "blind sql")
	if isSQLi && isHighSev {
		lp := strings.ToLower(proof)

		timingTerms := []string{"sleep(", "pg_sleep", "waitfor delay", "benchmark(",
			"time-based", "time based", "response time", "delay of", "took ", "seconds"}
		isTiming := false
		for _, t := range timingTerms {
			if strings.Contains(lp, t) {
				isTiming = true
				break
			}
		}

		// Hard confirmation = the bug produced data or a DB error, not just a delay.
		hardTerms := []string{"union select", "information_schema", "@@version", "dumped",
			"extracted", "sqlmap", "sqlstate", "sql syntax", "syntax error",
			"you have an error in your sql", "ora-0", "group_concat", "current_user", "database()"}
		isHard := false
		for _, t := range hardTerms {
			if strings.Contains(lp, t) {
				isHard = true
				break
			}
		}

		if isTiming && !isHard {
			// A real differential test compares MULTIPLE timings — a single-shot
			// SLEEP(N) is the exact false positive this gate rejects. Accept only
			// when there are >=2 distinct sleep magnitudes (e.g. SLEEP(0) vs
			// SLEEP(5) vs SLEEP(10)) OR an explicit baseline/control/repeat phrase.
			distinctMags := map[string]bool{}
			for _, m := range sleepMagnitudeRe.FindAllStringSubmatch(lp, -1) {
				distinctMags[m[1]] = true
			}
			hasDiff := len(distinctMags) >= 2
			if !hasDiff {
				diffMarkers := []string{"baseline", "differential", "vs sleep", "without payload",
					"control request", "control vs", "repeated", "averaged", "scales with",
					"scaled with", "consistent delay", "each run", "multiple trials", "proportional"}
				for _, d := range diffMarkers {
					if strings.Contains(lp, d) {
						hasDiff = true
						break
					}
				}
			}
			if !hasDiff {
				return "❌ REJECTED: Time-based SQLi proven by a single delayed response is a false positive risk — network jitter and rate-limiting produce the same delay. Provide a DIFFERENTIAL, repeated timing comparison (baseline / SLEEP(0) vs SLEEP(5) vs SLEEP(10), each run 2–3 times, delay scaling with the sleep value), OR confirm via data extraction (sqlmap --dump) or a database error string. Otherwise mark as info."
			}
		}
	}

	// Pattern 21: "HTTP method enforcement bypass" / broken access control inferred
	// purely from status codes. A 200 on POST/PUT/PATCH/DELETE/OPTIONS/HEAD — especially
	// with an empty body — is NOT proof of access. It is almost always a CORS preflight
	// or catch-all handler that does nothing: no state changes, no data returned.
	// OPTIONS/HEAD returning 200 is normal, RFC-correct behavior. Require evidence of a
	// real state change or returned data before allowing medium+.
	methodWords := []string{" post ", " put ", " patch ", " delete ", "options", "head request", "non-get"}
	methodHits := 0
	combinedAC := lower + " " + strings.ToLower(proof)
	for _, m := range methodWords {
		if strings.Contains(combinedAC, m) {
			methodHits++
		}
	}
	isMethodBypass := (strings.Contains(lower, "method") &&
		(strings.Contains(lower, "bypass") || strings.Contains(lower, "enforcement"))) ||
		(strings.Contains(lower, "access control") && methodHits >= 2) ||
		(strings.Contains(lower, "broken access control") && strings.Contains(combinedAC, "200"))
	if isMethodBypass && isHighSev {
		lp := strings.ToLower(proof)
		// Real impact = a state change happened or protected data was returned.
		impactSigns := []string{
			"another user", "other user", "user a's", "user b received", "as user b",
			"was deleted", "was modified", "was created", "was updated", "record changed",
			"session created", "session was created", "token issued", "token was generated",
			"balance", "response body contained", "json body", "returned sensitive",
			"leaked", "disclosed", "extracted", "modified the", "deleted the", "created a new",
		}
		hasImpact := false
		for _, s := range impactSigns {
			if strings.Contains(lp, s) {
				hasImpact = true
				break
			}
		}
		if !hasImpact {
			return "❌ REJECTED: A 200 status on POST/PUT/PATCH/DELETE/OPTIONS/HEAD is NOT proof of broken access control. An empty 200 (common for CORS preflight and catch-all handlers) means the request did nothing — no state changed and no data was returned, and OPTIONS/HEAD returning 200 is normal. To report this, demonstrate an ACTUAL state change (data created/modified/deleted) or sensitive data returned by the non-GET method — compare the response body and side effects against an authenticated request. Otherwise mark as info."
		}
	}

	// Pattern 22: "SSRF" that is actually client-side. SSRF (CWE-918) requires the
	// SERVER to make the attacker-controlled request. If the request originates in
	// the victim's browser (client-side JS reading URL params, fetch from a bundle),
	// it is NOT SSRF — and a "token" the attacker supplies in the crafted URL cannot
	// be "stolen" (they already have it; the PoC is circular). Reject unless there's
	// server-side out-of-band / internal-resource evidence.
	isSSRF := strings.Contains(lower, "ssrf") ||
		strings.Contains(lower, "server-side request forgery") ||
		strings.Contains(lower, "server side request forgery") ||
		strings.Contains(lower, "cwe-918")
	if isSSRF && isHighSev {
		clientSideMarkers := []string{
			"client-side", "client side", "browser", "window.location", "document.location",
			"urlsearchparams", "bundle.js", "javascript bundle", "in the user's browser",
			"victim's browser", "frontend javascript", "runs in the browser", "executed in the browser",
		}
		isClientSide := false
		for _, mk := range clientSideMarkers {
			if strings.Contains(combinedAC, mk) {
				isClientSide = true
				break
			}
		}

		serverSideProof := []string{
			"callback received", "dns query", "interact.sh", "interactsh", "oast",
			"burp collaborator", "collaborator", "169.254.169.254", "/latest/meta-data", "metadata.google",
			"out-of-band", "pingback", "server made", "server-side request", "connected to the internal",
			"internal-only", "retrieved by the target", "127.0.0.1", "localhost", "10.0.0", "192.168",
			"internal host", "internal service", "internal ip", "ssrf confirmed", "fetched http",
			"webhook.site", "requestbin", "canarytoken", "burpcollaborator",
		}
		hasServerProof := false
		lp := strings.ToLower(proof)
		for _, m := range serverSideProof {
			if strings.Contains(lp, m) {
				hasServerProof = true
				break
			}
		}

		if isClientSide && !hasServerProof {
			return "❌ REJECTED: This is described as CLIENT-SIDE (browser JS reading URL params / fetch from a bundle), which is NOT SSRF. SSRF (CWE-918) requires the TARGET'S SERVER to make the attacker-controlled request — prove it with a server-side out-of-band callback (interact.sh/collaborator) or an internal-only resource retrieved BY THE TARGET (e.g. 169.254.169.254). Also note: a 'token' the attacker places in the crafted URL is attacker-supplied and cannot be 'stolen' — that PoC is circular. If a URL/redirect can be controlled client-side, classify it correctly (open redirect / client-side issue), not SSRF, and only if a real victim secret is exposed."
		}
	}

	// Pattern 23: OpenAPI/Swagger spec or API documentation exposure reported as
	// information disclosure. A publicly served API spec is by-design — major APIs
	// publish it to generate SDKs/Postman collections, and the same file is usually
	// served on production and linked from public docs. Exposed FIELD/PARAMETER
	// NAMES (api_key, webhook_secret) are schema labels, NOT secret values. Reject
	// unless an actual secret VALUE is exposed.
	isAPIDocs := strings.Contains(lower, "openapi") ||
		strings.Contains(lower, "swagger") ||
		strings.Contains(lower, "/openapi.json") ||
		strings.Contains(lower, "api documentation") ||
		strings.Contains(lower, "api specification") ||
		strings.Contains(lower, "api spec") ||
		strings.Contains(lower, "redoc") ||
		strings.Contains(lower, "api-docs") ||
		strings.Contains(lower, "wadl")
	if isAPIDocs && isHighSev {
		lp := strings.ToLower(proof)
		// A real leak = actual secret VALUES embedded in the spec, not field names.
		valueLeak := []string{"sk_live", "sk_test", "bearer ey", "aws_secret", "akia",
			"-----begin", "secret value:", "token value:", "actual key", "ghp_", "xoxb-",
			"password:", "leaked credential", "hardcoded secret"}
		hasValueLeak := false
		for _, m := range valueLeak {
			if strings.Contains(lp, m) {
				hasValueLeak = true
				break
			}
		}
		if !hasValueLeak {
			return "❌ REJECTED: A publicly served OpenAPI/Swagger spec or API documentation is by-design, not information disclosure (CWE-200). Major APIs publish their spec to generate SDKs and Postman collections, the same file is typically served on production, and it is often linked from public docs. Exposed FIELD/PARAMETER names (e.g. api_key, webhook_secret) are schema labels, NOT secret values — knowing a field is named 'api_key' does not leak anyone's key. Only report if actual secret VALUES are embedded in the spec, or it exposes genuinely internal/undocumented endpoints that themselves leak data without auth."
		}
	}

	return ""
}

// dbmsErrorSignatures are distinctive strings emitted by database engines when a
// malformed query — typically an injected quote breaking the SQL syntax — reaches
// the server. They are the tell of an error-based SQL-injection point:
//
//	MySQL             → "you have an error in your sql", "sql syntax", "warning: mysql"
//	generic JDBC/ODBC → "sqlstate"
//	Oracle            → "ora-0"
//	Postgres          → "psqlexception", "quoted string not properly terminated"
//	SQLite            → "sqlite3::"
//	MSSQL             → "unclosed quotation mark after the character string"
//
// A benign web response does not emit these by accident, so a response that
// contains one after a quote injection proves the input reaches a SQL query
// unsanitized. Defined once here as the single source of truth: the concrete-
// impact indicators below embed it, and the agent's verify_sqli tool matches on
// it via LooksLikeSQLError so the detector and the reporting gate never drift.
var dbmsErrorSignatures = []string{
	"you have an error in your sql", "sql syntax", "sqlstate", "ora-0",
	"psqlexception", "sqlite3::", "unclosed quotation mark after the character string",
	"quoted string not properly terminated", "warning: mysql",
}

// LooksLikeSQLError reports whether text contains a DBMS error signature (see
// dbmsErrorSignatures) — i.e. the response looks like a database engine choked on
// a malformed query, the hallmark of error-based SQL injection.
func LooksLikeSQLError(text string) bool {
	lower := strings.ToLower(text)
	for _, sig := range dbmsErrorSignatures {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

// concreteImpactIndicators are unambiguous exploitation OUTCOMES. A match here
// means the target actually produced impact (command output, extracted data,
// stolen session material, an OOB hit). Used by hasStrongEvidence to gauge the
// strength of the AGENT'S OWN first-party proof (where a Set-Cookie/token is
// legitimately part of a demonstrated credential-theft exploit).
var concreteImpactIndicators = append([]string{
	// Data exfiltration outcome
	"extracted", "dumped", "exfiltrated",
	// System file / command-execution output
	"root:", "uid=", "gid=", "/etc/passwd", "/etc/shadow", "/proc/self",
	"password hash", "/bin/bash",
	// OS command-execution output (RCE / command injection). These are highly
	// distinctive strings that a benign web response does not emit by accident,
	// so they reliably prove an injected command actually ran:
	//   uname -a → "... x86_64 GNU/Linux";  uptime/top → "load average";
	//   Windows: whoami → "nt authority\\...";  dir → "Volume Serial Number";
	//   ipconfig → "Windows IP Configuration";  ver → "Microsoft Windows [Version".
	"gnu/linux", "load average", "nt authority\\", "volume serial number",
	"windows ip configuration", "microsoft windows [version",
	// SQL data extraction
	"union select", "information_schema", "@@version", "sqlmap",
	// (error-based SQLi DBMS errors are appended from dbmsErrorSignatures below)
	// Credential / session theft (concrete)
	"set-cookie:", "document.cookie", "session_id=", "access_token", "refresh_token",
	// SSRF / internal access (concrete targets/content)
	"169.254.169.254", "/latest/meta-data", "metadata.google.internal",
	// Out-of-band callbacks
	"callback received", "dns query", "burp collaborator",
	"interact.sh", "interactsh", "oast", "http request received", "pingback",
}, dbmsErrorSignatures...)

// reproducedImpactIndicators is the STRICT subset used to AUTO-CONFIRM a finding
// from the independent verifier's own re-test output. It deliberately omits the
// generic session/credential markers (Set-Cookie, session_id, access_token,
// refresh_token, document.cookie): those appear on ordinary login pages and any
// baseline request, so matching them would let an unrelated response falsely
// validate a finding the verifier never actually reproduced. Only unambiguous
// command-execution, data-exfiltration, SQL-extraction, cloud-metadata, and
// out-of-band-callback outcomes qualify here.
var reproducedImpactIndicators = append([]string{
	"extracted", "dumped", "exfiltrated",
	"root:", "uid=", "gid=", "/etc/passwd", "/etc/shadow", "/proc/self",
	"password hash", "/bin/bash",
	// OS command-execution output (see concreteImpactIndicators for rationale).
	"gnu/linux", "load average", "nt authority\\", "volume serial number",
	"windows ip configuration", "microsoft windows [version",
	"union select", "information_schema", "@@version", "sqlmap",
	// (error-based SQLi DBMS errors are appended from dbmsErrorSignatures below)
	"169.254.169.254", "/latest/meta-data", "metadata.google.internal",
	"callback received", "dns query", "burp collaborator",
	"interact.sh", "interactsh", "oast", "http request received", "pingback",
}, dbmsErrorSignatures...)

// HasConcreteImpact reports whether text contains an unambiguous, non-generic
// exploitation outcome (see reproducedImpactIndicators). The verifier uses this
// — NOT the looser hasStrongEvidence — to auto-confirm from its own re-test
// output, so a stray Set-Cookie on a login page can never validate a finding.
func HasConcreteImpact(text string) bool {
	lower := strings.ToLower(text)
	for _, ind := range reproducedImpactIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// hasStrongEvidence checks if the proof actually contains meaningful exploitation evidence.
// Uses impact-based analysis rather than just keyword matching.
func hasStrongEvidence(severity, proof, description string) bool {
	if proof == "" {
		return false
	}

	lowerProof := strings.ToLower(proof)
	lowerDesc := strings.ToLower(description)
	combined := lowerProof + " " + lowerDesc

	// Severity-specific keywords
	keywords, ok := evidenceKeywords[severity]
	if !ok {
		return true // low/info don't need strong evidence
	}
	for _, kw := range keywords {
		if strings.Contains(lowerProof, kw) {
			return true
		}
	}

	// Impact-based indicators — concrete exploitation OUTCOMES only.
	for _, ind := range concreteImpactIndicators {
		if strings.Contains(lowerProof, ind) {
			return true
		}
	}

	// If proof references concrete impact in the description
	impactPhrases := []string{"account takeover", "data breach", "privilege escalation",
		"arbitrary code", "remote execution", "unauthorized access",
		"sensitive data", "personal information", "financial", "payment",
		"credential", "authentication bypass", "session hijack"}
	for _, phrase := range impactPhrases {
		if strings.Contains(combined, phrase) {
			return true
		}
	}

	return false
}

func formatValidMethods() string {
	methods := make([]string, 0, len(validVerificationMethods))
	for m := range validVerificationMethods {
		methods = append(methods, m)
	}
	return strings.Join(methods, ", ")
}

// GetVulnerabilities returns all reported vulnerabilities for the active scan context.
func GetVulnerabilities() []Vulnerability {
	store := getStore()
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]Vulnerability, len(store.vulns))
	copy(result, store.vulns)
	return result
}

// GetVulnerabilitiesForContext returns vulns for a specific context ID.
func GetVulnerabilitiesForContext(contextID string) []Vulnerability {
	store := getStoreForContext(contextID)
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]Vulnerability, len(store.vulns))
	copy(result, store.vulns)
	return result
}

// ResetVulnerabilities clears the vulnerability list for the active scan context.
func ResetVulnerabilities() {
	store := getStore()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.vulns = nil
}

// ResetVulnerabilitiesForContext clears vulns for a specific context ID.
func ResetVulnerabilitiesForContext(contextID string) {
	store := getStoreForContext(contextID)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.vulns = nil
}

// CleanupContext removes the store for a context that has been deactivated.
// Also removes any parent-context mapping registered for this context so the
// parentMap does not leak entries across scan lifecycles.
func CleanupContext(contextID string) {
	storesMu.Lock()
	delete(stores, contextID)
	storesMu.Unlock()

	parentMap.Lock()
	delete(parentMap.m, contextID)
	parentMap.Unlock()

	findingVerifierMu.Lock()
	delete(findingVerifiers, contextID)
	findingVerifierMu.Unlock()
}

// PromoteToParent copies a single vulnerability from the child reporting
// context into the parent's reporting context if it isn't already there.
//
// Idempotent: if the parent already contains a vuln with the same ID, this
// is a no-op. Safe to call after every successful report_vulnerability so
// the parent aggregate stays current and survives a child panic before
// the broader MergeVulnsToContext can run at session finalization.
//
// Validates: Property 4 (panic-safe persistence) of the
// findings-consistency-and-pagination spec.
func PromoteToParent(childContextID, parentContextID, vulnID string) {
	if childContextID == "" || parentContextID == "" || vulnID == "" {
		return
	}
	if childContextID == parentContextID {
		return
	}

	src := getStoreByID(childContextID)
	src.mu.RLock()
	var found *Vulnerability
	for i := range src.vulns {
		if src.vulns[i].ID == vulnID {
			v := src.vulns[i]
			found = &v
			break
		}
	}
	src.mu.RUnlock()
	if found == nil {
		return
	}

	dst := getStoreByID(parentContextID)
	dst.mu.Lock()
	defer dst.mu.Unlock()
	for _, v := range dst.vulns {
		if v.ID == vulnID {
			return // already present
		}
	}
	// Skip semantic duplicates too, mirroring MergeVulnsToContext's behavior.
	if _, _, dup := findDuplicateVulnerability(dst.vulns, found.Title, found.Description, found.CVE, found.CWE, found.Target, found.Endpoint); dup {
		return
	}
	dst.vulns = append(dst.vulns, *found)
}

// promoteIfChildOfWildcard looks up the parent context registered for the
// child via SetParentContext and forwards to PromoteToParent. No-op if no
// parent has been declared for childCtxID.
func promoteIfChildOfWildcard(childCtxID, vulnID string) {
	parent := GetParentContext(childCtxID)
	if parent == "" {
		return
	}
	PromoteToParent(childCtxID, parent, vulnID)
}

// MergeVulnsToContext copies all vulnerabilities from srcContextID into dstContextID.
// Semantic duplicates are skipped. ID collisions are renumbered because each
// child context starts its own XALG-1 sequence.
func MergeVulnsToContext(srcContextID, dstContextID string) int {
	if srcContextID == "" || dstContextID == "" || srcContextID == dstContextID {
		return 0
	}

	// Read source vulns
	srcStore := getStoreForContext(srcContextID)
	srcStore.mu.RLock()
	srcVulns := make([]Vulnerability, len(srcStore.vulns))
	copy(srcVulns, srcStore.vulns)
	srcStore.mu.RUnlock()

	if len(srcVulns) == 0 {
		return 0
	}

	// Merge into destination, skipping duplicates
	dstStore := getStoreForContext(dstContextID)
	dstStore.mu.Lock()
	defer dstStore.mu.Unlock()

	seenIDs := make(map[string]bool, len(dstStore.vulns))
	for _, v := range dstStore.vulns {
		seenIDs[v.ID] = true
	}

	added := 0
	for _, v := range srcVulns {
		if _, _, duplicate := findDuplicateVulnerability(dstStore.vulns, v.Title, v.Description, v.CVE, v.CWE, v.Target, v.Endpoint); duplicate {
			continue
		}
		if seenIDs[v.ID] {
			nextID := len(dstStore.vulns) + 1
			for {
				v.ID = fmt.Sprintf("XALG-%d", nextID)
				if !seenIDs[v.ID] {
					break
				}
				nextID++
			}
		}
		dstStore.vulns = append(dstStore.vulns, v)
		seenIDs[v.ID] = true
		added++
	}
	return added
}

// GetVulnsJSON returns vulnerabilities as JSON for the active scan context.
func GetVulnsJSON() string {
	store := getStore()
	store.mu.RLock()
	defer store.mu.RUnlock()
	data, err := json.Marshal(store.vulns)
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to marshal vulnerabilities: %s"}`, err.Error())
	}
	return string(data)
}

// severityRank maps severity strings to numeric levels for comparison.
var severityRank = map[string]int{
	"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

// severityFromCVSS returns the HackerOne-standard severity label for a CVSS 3.1 score.
// Critical: 9.0-10.0, High: 7.0-8.9, Medium: 4.0-6.9, Low: 0.1-3.9, None/Info: 0.0
func severityFromCVSS(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "critical"
	case cvss >= 7.0:
		return "high"
	case cvss >= 4.0:
		return "medium"
	case cvss > 0:
		return "low"
	default:
		return "info"
	}
}

// classifySeverity enforces maximum severity caps based on vulnerability type.
// Returns the (possibly capped) severity and a reason if it was changed.
func classifySeverity(title, description, severity, proof string) (string, string) {
	rank, ok := severityRank[severity]
	if !ok || rank <= 1 {
		return severity, "" // info/low — no need to cap further
	}

	lower := strings.ToLower(title + " " + description)
	lowerProof := strings.ToLower(proof)

	// Normalize to canonical vuln type for consistent classification
	// regardless of how the LLM titles the finding. This prevents
	// "Stored XSS in CRM" and "Contact Injection / Stored XSS" from
	// getting different severity caps.
	vulnType := extractVulnType(title, description)

	// ── INFO-only findings (max severity: info) ──
	infoOnlyPatterns := []struct {
		keywords []string
		reason   string
	}{
		{[]string{"missing header", "security header", "x-frame-options missing", "csp missing",
			"hsts missing", "x-content-type missing", "referrer-policy missing",
			"permissions-policy missing", "x-xss-protection missing"},
			"Missing security headers are informational — not directly exploitable"},
		{[]string{"version disclosure", "server version", "software version", "banner grabbing",
			"x-powered-by", "server header disclosure", "technology detected"},
			"Version/technology disclosure is informational unless tied to a specific exploited CVE"},
		{[]string{"directory listing", "directory index", "index of /"},
			"Directory listing is informational unless sensitive files are exposed and accessed"},
		{[]string{"self-xss", "self xss"},
			"Self-XSS only affects the user's own session — not exploitable against others"},
		{[]string{"debug mode", "debug enabled", "stack trace exposed", "verbose error"},
			"Debug/error disclosure is informational unless it leaks credentials or enables further exploitation"},
		{[]string{"robots.txt", "sitemap.xml", "crossdomain.xml"},
			"Configuration file disclosure is informational"},
		{[]string{"ssl weak", "tls weak", "weak cipher", "tls 1.0", "tls 1.1", "ssl certificate"},
			"SSL/TLS configuration issues are informational — not directly exploitable in practice"},
		{[]string{"email disclosure", "email address found", "email harvesting"},
			"Email disclosure is informational"},
		{[]string{"dns zone transfer", "zone transfer"},
			"DNS zone transfer is informational in most contexts"},
		{[]string{"writekey", "write_key", "write key", "analytics key", "segment key", "analytics api key"},
			"Analytics writeKeys are public client-side tokens — not a security vulnerability"},
		// NOTE: rate limit findings are handled separately below (low-cap with
		// sensitive-endpoint exception) instead of blanket info-only.
		{[]string{"sentry dsn", "ingest.sentry.io", "sentry.io/api"},
			"Sentry DSN is a public client-side key — not a vulnerability"},
		{[]string{"public_env", "next_public_", "react_app_", "window.__singletons"},
			"Client-side environment variables (PUBLIC_ENV, NEXT_PUBLIC_*) are public by design"},
	}

	for _, p := range infoOnlyPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				return "info", p.reason
			}
		}
	}

	// ── LOW-cap findings (max severity: low) — HackerOne standard ──
	lowCapPatterns := []struct {
		keywords  []string
		exception func() bool
		reason    string
	}{
		{[]string{"cors", "cross-origin resource sharing", "access-control-allow-origin"},
			func() bool {
				// Exception: CORS + credential theft proof = allow higher severity
				theftKeywords := []string{"cookie", "token", "steal", "exfiltrate", "xmlhttprequest", "fetch(", "document.cookie"}
				for _, tk := range theftKeywords {
					if strings.Contains(lowerProof, tk) {
						return true
					}
				}
				return false
			},
			"CORS alone is low severity (CVSS 2.0-3.9) — needs proven cookie/token theft for higher"},
		{[]string{"clickjacking", "click jacking", "ui redressing"},
			nil,
			"Clickjacking is low severity (CVSS 2.0-3.9) per HackerOne — limited real-world impact"},
		{[]string{"cookie without httponly", "cookie missing httponly", "cookie flag", "cookie attribute", "missing secure flag"},
			nil,
			"Missing cookie flags alone are low severity (CVSS 2.0-3.9)"},
		{[]string{"path disclosure", "full path", "internal path"},
			nil,
			"Internal path disclosure is low severity (CVSS 2.0-3.9)"},
		// Open redirect: HackerOne treats standalone open redirects as LOW
		{[]string{"open redirect", "url redirect", "unvalidated redirect"},
			func() bool {
				// Exception: redirect chained with OAuth/token theft = allow higher
				chainKeywords := []string{"oauth", "token", "ssrf", "chain", "steal", "authorization_code", "code="}
				for _, ck := range chainKeywords {
					if strings.Contains(lowerProof, ck) || strings.Contains(lower, ck) {
						return true
					}
				}
				return false
			},
			"Open redirect is low severity (CVSS 2.0-3.9) per HackerOne — needs OAuth/token chain for higher"},
		// CRLF: HackerOne treats as low unless chained
		{[]string{"crlf injection", "http response splitting"},
			func() bool {
				chainKeywords := []string{"cache poison", "xss", "session fixation", "header injection"}
				for _, ck := range chainKeywords {
					if strings.Contains(lowerProof, ck) || strings.Contains(lower, ck) {
						return true
					}
				}
				return false
			},
			"CRLF injection is low severity (CVSS 2.0-3.9) per HackerOne — needs cache poisoning or XSS chain for higher"},
		// Host header injection: low unless chained
		{[]string{"host header injection", "host header"},
			func() bool {
				chainKeywords := []string{"cache poison", "password reset", "email", "inject", "redirect"}
				for _, ck := range chainKeywords {
					if strings.Contains(lowerProof, ck) {
						return true
					}
				}
				return false
			},
			"Host header injection is low severity (CVSS 2.0-3.9) per HackerOne — needs password reset poisoning or cache poisoning chain for higher"},
		// Rate limiting: low unless on sensitive auth endpoints
		{[]string{"rate limit", "rate-limit", "no rate limit", "brute force", "brute-force",
			"account lockout", "missing rate limit", "unlimited requests", "no lockout"},
			func() bool {
				return isSensitiveEndpointContext(lower, lowerProof)
			},
			"Missing rate limiting is low severity (CVSS 2.0-3.9) on non-sensitive endpoints — on login/password-reset/OTP/2FA endpoints it can be higher"},
	}

	for _, p := range lowCapPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				if p.exception != nil && p.exception() {
					continue // exception met, allow higher severity
				}
				if rank > severityRank["low"] {
					return "low", p.reason
				}
			}
		}
	}

	// ── MEDIUM-cap findings (max severity: medium) — HackerOne standard ──
	medCapPatterns := []struct {
		keywords  []string
		exception func() bool
		reason    string
	}{
		{[]string{"reflected xss"},
			func() bool {
				// Exception: Reflected XSS → session hijack/ATO = allow high
				for _, kw := range []string{"account takeover", "session hijack", "cookie stolen", "admin access", "document.cookie"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"Reflected XSS is medium (CVSS 4.0-6.9) per HackerOne — needs proven session hijack for high"},
		{[]string{"dom xss", "dom-based xss"},
			func() bool {
				for _, kw := range []string{"account takeover", "session hijack", "cookie stolen", "admin access"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"DOM XSS is medium (CVSS 4.0-6.9) per HackerOne — needs proven session hijack for high"},
		{[]string{"csrf", "cross-site request forgery"},
			func() bool {
				// Exception: CSRF on critical action = allow high
				for _, kw := range []string{"password", "admin", "delete account", "transfer", "payment", "email change", "role change"} {
					if strings.Contains(lower, kw) || strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"CSRF is medium (CVSS 4.0-6.9) per HackerOne — needs critical action impact (password change, payment) for high"},
		{[]string{"information disclosure", "info disclosure", "sensitive data exposure"},
			func() bool {
				// Exception: PII/credentials leaked = allow high
				for _, kw := range []string{"password", "credential", "api key", "secret", "token", "pii", "ssn", "credit card"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"Information disclosure is medium (CVSS 4.0-6.9) per HackerOne — needs PII/credential exposure for high"},
	}

	for _, p := range medCapPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				if p.exception != nil && p.exception() {
					continue // exception met, allow higher severity
				}
				if rank > severityRank["medium"] {
					return "medium", p.reason
				}
			}
		}
	}

	// ── HIGH-cap findings (max severity: high) — HackerOne standard ──
	highCapPatterns := []struct {
		keywords  []string
		exception func() bool
		reason    string
	}{
		// Stored XSS: High on HackerOne unless it leads to mass ATO/RCE
		{[]string{"stored xss", "persistent xss"},
			func() bool {
				for _, kw := range []string{"admin", "rce", "mass", "worm", "all users", "account takeover"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"Stored XSS is high (CVSS 7.0-8.9) per HackerOne — needs admin access/mass ATO/RCE chain for critical"},
		// SSRF: High on HackerOne unless full internal access/cloud metadata
		{[]string{"ssrf", "server-side request forgery", "server side request forgery"},
			func() bool {
				for _, kw := range []string{"aws", "metadata", "169.254", "cloud", "credentials", "rce", "internal network", "full access"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"SSRF is high (CVSS 7.0-8.9) per HackerOne — needs cloud metadata/credential exposure or RCE for critical"},
		// IDOR: High on HackerOne unless mass data exposure
		{[]string{"idor", "insecure direct object"},
			func() bool {
				for _, kw := range []string{"all users", "mass", "database dump", "admin access", "full", "account takeover"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"IDOR is high (CVSS 7.0-8.9) per HackerOne — needs mass data dump or admin access for critical"},
		// File Inclusion: High unless RCE demonstrated
		{[]string{"file inclusion", "lfi", "local file inclusion", "path traversal", "directory traversal"},
			func() bool {
				for _, kw := range []string{"rce", "remote code", "shell", "/etc/shadow", "proc/self", "command execution"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"File inclusion is high (CVSS 7.0-8.9) per HackerOne — needs RCE or shadow file access for critical"},
		// Auth Bypass: High unless full admin access
		{[]string{"authentication bypass", "auth bypass", "login bypass"},
			func() bool {
				for _, kw := range []string{"admin", "root", "superuser", "full access", "all accounts"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"Auth bypass is high (CVSS 7.0-8.9) per HackerOne — needs admin/root access for critical"},
	}

	for _, p := range highCapPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				if p.exception != nil && p.exception() {
					continue // exception met, allow critical
				}
				if rank > severityRank["high"] {
					return "high", p.reason
				}
			}
		}
	}

	// ── vulnType-based fallback caps ──
	// If the keyword-based caps above didn't fire (e.g., the LLM titled the
	// finding "Contact Injection" instead of "Stored XSS"), apply caps based
	// on the canonical vuln type extracted from title + description. This
	// ensures consistent classification regardless of LLM title framing.
	switch vulnType {
	case "xss":
		// Distinguish stored vs reflected/DOM
		isStored := strings.Contains(lower, "stored") || strings.Contains(lower, "persistent") ||
			strings.Contains(lower, "stores") || strings.Contains(lower, "persist") ||
			strings.Contains(lower, "permanent") || strings.Contains(lower, "saved in")
		if isStored {
			// Stored XSS → high cap (same as highCapPatterns above)
			if rank > severityRank["high"] {
				return "high", "Stored XSS is high (CVSS 7.0-8.9) per HackerOne — needs admin access/mass ATO/RCE chain for critical"
			}
		} else {
			// Reflected/DOM/generic XSS → medium cap (same as medCapPatterns above)
			if rank > severityRank["medium"] {
				return "medium", "Reflected/DOM XSS is medium (CVSS 4.0-6.9) per HackerOne — needs session hijack proof for high"
			}
		}
	case "csrf":
		if rank > severityRank["medium"] {
			return "medium", "CSRF is medium (CVSS 4.0-6.9) per HackerOne — needs critical state change for high"
		}
	case "info_disclosure":
		if rank > severityRank["medium"] {
			return "medium", "Information disclosure is medium (CVSS 4.0-6.9) per HackerOne — needs PII/credential exposure for high"
		}
	case "ssrf":
		if rank > severityRank["high"] {
			return "high", "SSRF is high (CVSS 7.0-8.9) per HackerOne — needs cloud metadata/RCE for critical"
		}
	case "idor":
		if rank > severityRank["high"] {
			return "high", "IDOR is high (CVSS 7.0-8.9) per HackerOne — needs mass data dump for critical"
		}
	case "lfi":
		if rank > severityRank["high"] {
			return "high", "File inclusion is high (CVSS 7.0-8.9) per HackerOne — needs RCE for critical"
		}
	case "auth_bypass":
		if rank > severityRank["high"] {
			return "high", "Auth bypass is high (CVSS 7.0-8.9) per HackerOne — needs admin/root access for critical"
		}
	case "cors":
		if rank > severityRank["low"] {
			return "low", "CORS alone is low severity (CVSS 2.0-3.9) — needs proven cookie/token theft for higher"
		}
	case "open_redirect":
		if rank > severityRank["low"] {
			return "low", "Open redirect is low severity (CVSS 2.0-3.9) per HackerOne — needs OAuth/token chain for higher"
		}
	case "clickjacking":
		if rank > severityRank["low"] {
			return "low", "Clickjacking is low severity (CVSS 2.0-3.9) per HackerOne"
		}
	case "crlf":
		if rank > severityRank["low"] {
			return "low", "CRLF injection is low severity (CVSS 2.0-3.9) per HackerOne"
		}
	case "missing_header", "version_disclosure":
		return "info", "Missing headers/version disclosure are informational"
	}

	return severity, "" // no cap needed
}

// isSensitiveEndpointContext returns true when the title+description or proof
// text indicates the rate-limit issue targets a security-sensitive endpoint
// (login, password reset, OTP/2FA verification, signup, account recovery, etc.).
// These are areas where missing rate limiting can lead to credential stuffing,
// brute-force attacks, or OTP bypass — making the finding genuinely impactful.
func isSensitiveEndpointContext(lowerText, lowerProof string) bool {
	combined := lowerText + " " + lowerProof
	sensitiveKeywords := []string{
		// Authentication
		"login", "signin", "sign-in", "sign in", "authenticate",
		"authentication", "credential", "credential stuffing",
		// Password reset / recovery
		"password reset", "forgot password", "reset password",
		"password recovery", "account recovery", "reset token",
		"reset link",
		// OTP / 2FA / MFA
		"otp", "one-time password", "one time password",
		"2fa", "two-factor", "two factor", "mfa", "multi-factor",
		"multi factor", "verification code", "sms code",
		"totp", "authenticator code", "magic link",
		// Signup / registration
		"signup", "sign-up", "sign up", "registration", "register",
		"create account", "new account",
		// Email / phone verification
		"email verification", "phone verification", "verify email",
		"verify phone", "confirmation code",
		// Sensitive API endpoints
		"/auth", "/login", "/signin", "/signup", "/register",
		"/reset", "/forgot", "/otp", "/verify", "/2fa", "/mfa",
		"/token", "/session",
		// Payment / financial
		"payment", "checkout", "transaction", "purchase",
		"coupon", "promo code", "discount code", "gift card",
	}
	for _, kw := range sensitiveKeywords {
		if strings.Contains(combined, kw) {
			return true
		}
	}
	return false
}

// extractVulnType extracts a canonical vulnerability type from title/description
// for deduplication purposes. Returns empty string if type can't be determined.
func extractVulnType(title, description string) string {
	lower := strings.ToLower(title + " " + description)

	vulnTypes := []struct {
		typeName string
		keywords []string
	}{
		{"xss", []string{"xss", "cross-site scripting", "cross site scripting", "reflected xss", "stored xss", "dom xss", "script injection"}},
		{"sqli", []string{"sql injection", "sqli", "sql inject", "blind sql", "union select", "error-based sql"}},
		{"ssrf", []string{"ssrf", "server-side request forgery", "server side request forgery"}},
		{"idor", []string{"idor", "insecure direct object", "broken access control", "unauthorized access"}},
		{"lfi", []string{"local file inclusion", "lfi", "file inclusion", "path traversal", "directory traversal", "path disclosure", "physical path"}},
		{"rfi", []string{"remote file inclusion", "rfi"}},
		{"rce", []string{"remote code execution", "rce", "command injection", "os command", "code execution"}},
		{"csrf", []string{"csrf", "cross-site request forgery", "cross site request forgery"}},
		{"xxe", []string{"xxe", "xml external entity"}},
		{"open_redirect", []string{"open redirect", "url redirect", "unvalidated redirect"}},
		{"auth_bypass", []string{"authentication bypass", "auth bypass", "login bypass", "auth flow"}},
		{"info_disclosure", []string{"information disclosure", "info disclosure", "sensitive data exposure", "data leak", "api key", "credential leak", "password leak", "exposed secret", "token leak", "verbose error"}},
		{"missing_header", []string{"missing header", "security header", "x-frame-options", "content-security-policy", "hsts", "x-content-type"}},
		{"version_disclosure", []string{"version disclosure", "server header", "x-powered-by", "technology disclosure", "fingerprint"}},
		{"subdomain_takeover", []string{"subdomain takeover", "dangling dns", "unclaimed subdomain"}},
		{"clickjacking", []string{"clickjacking", "ui redressing"}},
		{"cors", []string{"cors", "cross-origin resource sharing", "cross origin"}},
		{"crlf", []string{"crlf injection", "http response splitting"}},
		{"ssti", []string{"ssti", "server-side template injection", "template injection"}},
		{"deserialization", []string{"deserialization", "insecure deserialization", "object injection"}},
	}

	for _, vt := range vulnTypes {
		for _, kw := range vt.keywords {
			if strings.Contains(lower, kw) {
				return vt.typeName
			}
		}
	}
	return ""
}

// cweDigitsRe pulls the numeric portion out of a CWE identifier so "CWE-79",
// "cwe 79", and "79" all normalize to "79".
var cweDigitsRe = regexp.MustCompile(`[0-9]+`)

// cweToVulnType maps a CWE identifier to the same canonical class names
// extractVulnType uses, so deduplication can still recognize a finding's class
// when the title/description carry no class keyword but a CWE is set. Only
// high-confidence, common mappings are included; anything unmapped yields "".
func cweToVulnType(cwe string) string {
	switch cweDigitsRe.FindString(cwe) {
	case "79":
		return "xss"
	case "89":
		return "sqli"
	case "918":
		return "ssrf"
	case "22":
		return "lfi"
	case "98":
		return "rfi"
	case "77", "78", "94", "95":
		return "rce"
	case "352":
		return "csrf"
	case "611":
		return "xxe"
	case "601":
		return "open_redirect"
	case "287", "288", "305", "306":
		return "auth_bypass"
	case "200", "209", "532":
		return "info_disclosure"
	case "284", "285", "566", "639", "862", "863":
		return "idor"
	case "1021":
		return "clickjacking"
	case "942":
		return "cors"
	case "93", "113":
		return "crlf"
	case "1336":
		return "ssti"
	case "502":
		return "deserialization"
	default:
		return ""
	}
}

// extractVulnTypeWithCWE is extractVulnType with a CWE fallback: when the
// title/description don't reveal a class, the finding's CWE (if any) is mapped
// to one. This tightens dedup for findings whose titles omit the class keyword
// (e.g. "Unauthenticated contact creation" with CWE-79) so they still collapse
// onto the same-class report instead of each triggering a fresh verification.
func extractVulnTypeWithCWE(title, description, cwe string) string {
	if t := extractVulnType(title, description); t != "" {
		return t
	}
	return cweToVulnType(cwe)
}

// normalizeEndpoint strips query params, fragments, and trailing slashes
// so "/api/search?q=test" and "/api/search?q=foo" match as the same endpoint.
func normalizeEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}

	// Strip query parameters
	if idx := strings.Index(endpoint, "?"); idx >= 0 {
		endpoint = endpoint[:idx]
	}
	// Strip fragment
	if idx := strings.Index(endpoint, "#"); idx >= 0 {
		endpoint = endpoint[:idx]
	}
	// Strip trailing slashes
	endpoint = strings.TrimRight(endpoint, "/")
	// Lowercase for consistent comparison
	return strings.ToLower(endpoint)
}

// idPathSegment matches a single path segment that is an opaque per-object
// identifier — a pure number, a UUID, or a long hex string (e.g. a Mongo
// ObjectId). These vary per object instance, so the SAME finding across many
// IDs (/orders/1, /orders/2, /orders/9f3e…-uuid) would otherwise look like
// distinct endpoints and each trigger a fresh, expensive verification plus a
// separate stored finding.
var (
	uuidPathSegment = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexPathSegment  = regexp.MustCompile(`^[0-9a-f]{16,}$`)
	numPathSegment  = regexp.MustCompile(`^\d+$`)
)

// isIDPathSegment reports whether a path segment looks like an opaque object
// identifier. It is deliberately conservative: version-like ("v1", "v2") and
// named segments ("users", "api") never match, so distinct endpoints are not
// collapsed — only object-ID variants of the same endpoint are.
func isIDPathSegment(seg string) bool {
	if seg == "" {
		return false
	}
	if numPathSegment.MatchString(seg) {
		return true
	}
	// normalizeEndpoint already lowercased, but be defensive for direct callers.
	low := strings.ToLower(seg)
	return uuidPathSegment.MatchString(low) || hexPathSegment.MatchString(low)
}

// templatePathParams collapses opaque per-object identifier segments in a path
// to "{id}", so ID variants of the same endpoint share a key. It expects an
// already query/fragment-stripped, lowercased path (see dedupEndpointKey).
func templatePathParams(path string) string {
	if path == "" || !strings.Contains(path, "/") {
		return path
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if isIDPathSegment(s) {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/")
}

// dedupEndpointKey is normalizeEndpoint plus path-parameter templating. It is
// used ONLY for duplicate comparison — never for the stored or displayed
// endpoint, which must keep the real object id for the PoC to be reproducible.
func dedupEndpointKey(endpoint string) string {
	return templatePathParams(normalizeEndpoint(endpoint))
}

func normalizeFindingText(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}
