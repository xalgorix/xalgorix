// Package agent — oob_verify.go implements verify_oob: a ledger-integrated
// out-of-band (OAST) verifier for BLIND vulnerabilities.
//
// Blind injection is where autonomous scanners are weakest (MAPTA reports 0% on
// blind SQLi) because in-band responses reveal nothing — the only proof is the
// target reaching out to a callback the attacker controls. The existing
// oob_callback tool mints callbacks and polls raw interactions; verify_oob adds
// the missing piece: it correlates a token to a specific hypothesis, applies a
// class-aware verdict over the interactions, and records the blind-execution
// proof in the shared ledger so it flows through the same scheduling +
// precision finish-gate as every other finding.
//
// Verdict policy (deliberately conservative to preserve precision-over-volume):
//   - SSRF: only an ASSESSED NON-SCANNER HTTP interaction confirms. DNS-only,
//     scanner-origin, and origin-unassessed hits are leads, not proof — this
//     mirrors oob_callback's own SSRF guidance (the scanner can follow a
//     redirect to its own callback).
//   - blind RCE / CMDi: the caller must additionally supply the exact
//     callback-bearing payload and identify an OS/runtime/template execution
//     primitive. A RUNSCRIPT/URL/XML/webhook fetch is rejected as RCE evidence:
//     it proves the fetch primitive, not arbitrary code execution.
//   - XXE / SQLi / XSS: the callback is embedded in a class-specific
//     target-side payload, so a genuine non-scanner callback can prove that
//     primitive executed. Scanner-origin-only hits do NOT confirm.
package agent

import (
	"fmt"
	"strings"

	oobsrv "github.com/xalgord/xalgorix/v4/internal/oob"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

type oobPollFunc func(string) []oobsrv.Interaction

// registerOOBVerifyTool registers the Agent-bound verify_oob tool. It is
// Agent-bound so it can record to the shared ledger; it makes no outbound
// request itself (it only reads the local OAST interaction store), so it needs
// no scope gate.
func (a *Agent) registerOOBVerifyTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "verify_oob",
		Description: "Confirm a BLIND vulnerability out-of-band and record it in the ledger. Workflow: (1) oob_callback action=generate; (2) plant that callback in the exact target-side payload; (3) call verify_oob with token, vuln_class, endpoint, parameter, and the exact callback-bearing payload. For SSRF an assessed non-scanner HTTP interaction is required. For blind RCE/CMDi, execution_primitive and payload_evidence are mandatory: only os-command, runtime-api, or template-execution with a visible execution expression can prove RCE. RUNSCRIPT FROM/URL, XML SYSTEM, webhook/URL, database-network, or other fetch-only callbacks prove their actual SQL/XXE/SSRF primitive, never RCE. This is the primary confirmer for classes that leave no in-band signal.",
		Parameters: []tools.Parameter{
			{Name: "token", Description: "The token from oob_callback action=generate, planted in the payload.", Required: true},
			{Name: "vuln_class", Description: "Blind class under test: blind-sqli, blind-rce, blind-cmdi, xxe, blind-ssrf (or ssrf), blind-xss.", Required: true},
			{Name: "endpoint", Description: "Target endpoint where the payload was injected.", Required: false},
			{Name: "parameter", Description: "Parameter/input that carried the payload.", Required: false},
			{Name: "role", Description: "Auth context (anonymous/user/admin) if relevant.", Required: false},
			{Name: "execution_primitive", Description: "Required for blind-rce/blind-cmdi: os-command, runtime-api, or template-execution. Fetch-only primitives (database-network, xml-entity, server-fetch) cannot verify RCE.", Required: false},
			{Name: "payload_evidence", Description: "Required for blind-rce/blind-cmdi: the exact callback-bearing injected command/expression. It must contain the token and an OS/runtime/template execution marker. Do not describe a hypothetical payload.", Required: false},
		},
		Execute: a.oobVerifyTool,
	})
}

func (a *Agent) oobVerifyTool(args map[string]string) (tools.Result, error) {
	token := strings.TrimSpace(args["token"])
	if token == "" {
		return tools.Result{Error: "token is required (mint one with oob_callback action=generate and plant it in your payload first)"}, nil
	}
	class := normalizeBlindClass(args["vuln_class"])
	if class == "" {
		return tools.Result{Error: "vuln_class is required (e.g. blind-sqli, blind-rce, blind-cmdi, xxe, blind-ssrf)"}, nil
	}
	primitive := normalizeExecutionPrimitive(args["execution_primitive"])
	payload := strings.TrimSpace(args["payload_evidence"])
	if err := validateOOBExecutionAttribution(token, class, primitive, payload); err != nil {
		return tools.Result{Error: err.Error(), Metadata: map[string]any{"oob_confirmed": false}}, nil
	}
	hits := a.pollOOB(token)
	return a.finalizeOOBVerdict(token, class, strings.TrimSpace(args["endpoint"]), strings.TrimSpace(args["parameter"]), strings.TrimSpace(args["role"]), primitive, payload, hits), nil
}

func (a *Agent) pollOOB(token string) []oobsrv.Interaction {
	if a.oobPollFn != nil {
		return a.oobPollFn(token)
	}
	return oobsrv.Poll(token)
}

func normalizeExecutionPrimitive(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
}

func isExecutionOOBClass(class string) bool {
	class = normalizeBlindClass(class)
	return strings.Contains(class, "rce") || strings.Contains(class, "cmdi") ||
		strings.Contains(class, "command-injection") || strings.Contains(class, "code-execution")
}

// validateOOBExecutionAttribution prevents a callback from crossing a
// vulnerability-class boundary. In particular, a database engine fetching a
// RUNSCRIPT URL establishes SQL/database egress, but it does not establish
// that the fetched content was evaluated or that an OS command ran.
func validateOOBExecutionAttribution(token, class, primitive, payload string) error {
	if !isExecutionOOBClass(class) {
		return nil
	}
	allowed := primitive == "os-command" || primitive == "runtime-api" || primitive == "template-execution"
	if !allowed {
		return fmt.Errorf("blind RCE/CMDi verification requires execution_primitive=os-command, runtime-api, or template-execution; fetch-only callbacks (RUNSCRIPT/URL/XML/webhook/database-network) must be classified by the primitive they actually prove")
	}
	if payload == "" {
		return fmt.Errorf("blind RCE/CMDi verification requires payload_evidence containing the exact callback-bearing injected command/expression")
	}
	lowerPayload := strings.ToLower(payload)
	if token == "" || !strings.Contains(lowerPayload, strings.ToLower(token)) {
		return fmt.Errorf("payload_evidence must contain the exact OAST token so the callback can be bound to this execution attempt")
	}
	fetchOnlyMarkers := []string{
		"runscript from", "runscript%20from", "<!entity", "<!doctype", "webhook", "database-network", "server-fetch",
	}
	for _, marker := range fetchOnlyMarkers {
		if strings.Contains(lowerPayload, marker) {
			return fmt.Errorf("payload_evidence shows a fetch-only primitive (%s), not OS/runtime/template code execution; verify and report the SQL/XXE/SSRF primitive instead of RCE", marker)
		}
	}
	executionMarkers := []string{
		"runtime.getruntime().exec", "processbuilder", "child_process", "os.system", "shell_exec", "popen(", "system(", "exec(",
		"/bin/sh", "cmd.exe", "powershell", "invoke-webrequest", "certutil", "curl ", "wget ", "nslookup ", "dig ", "ping ",
		"$(", "`curl", "`wget", "`nslookup", "`dig", "`ping",
	}
	for _, marker := range executionMarkers {
		if strings.Contains(lowerPayload, marker) {
			return nil
		}
	}
	// Java-native network expression inside an injected runtime trigger (the
	// H2/Metabase class of blind RCE): java.net.URL plus openConnection/
	// openStream/getContent is a runtime-api execution primitive — the
	// target's JVM executed attacker-injected code to originate the
	// callback, which a fetch-only DB feature (RUNSCRIPT FROM) cannot do.
	if strings.Contains(lowerPayload, "java.net.url") {
		for _, marker := range []string{"openconnection", "openstream", "getcontent"} {
			if strings.Contains(lowerPayload, marker) {
				return nil
			}
		}
	}
	return fmt.Errorf("payload_evidence contains the token but no recognizable OS/runtime/template execution expression; a URL fetch alone cannot verify RCE/CMDi")
}

// oobTally summarizes a set of interactions by provenance.
type oobTally struct {
	nonScannerHTTP int
	scannerHTTP    int
	unassessedHTTP int
	dns            int
	total          int
}

func tallyOOB(hits []oobsrv.Interaction) oobTally {
	var t oobTally
	for _, h := range hits {
		t.total++
		proto := strings.ToLower(strings.TrimSpace(h.Protocol))
		switch proto {
		case "dns":
			t.dns++
		case "http", "https":
			switch {
			case !h.OriginAssessed:
				t.unassessedHTTP++
			case h.ScannerOrigin:
				t.scannerHTTP++
			default:
				t.nonScannerHTTP++
			}
		default:
			// Unknown protocol with a resolvable remote is treated like DNS —
			// a lead, not scanner-attributable.
			t.dns++
		}
	}
	return t
}

// finalizeOOBVerdict applies the class-aware verdict, records ledger evidence
// when confirmed, and returns the tool result. Split from oobVerifyTool so the
// verdict + ledger logic is unit-testable with synthetic interactions.
func (a *Agent) finalizeOOBVerdict(token, class, endpoint, parameter, role, executionPrimitive, payloadEvidence string, hits []oobsrv.Interaction) tools.Result {
	if len(hits) == 0 {
		return tools.Result{
			Output:   fmt.Sprintf("No OOB interactions for token %s. If you just sent the payload, wait a few seconds and call verify_oob again. Sustained silence means the sink is not reaching the callback (not blind-exploitable over the tried egress, or egress is filtered).", token),
			Metadata: map[string]any{"oob_confirmed": false, "oob_hits": 0},
		}
	}

	t := tallyOOB(hits)
	ssrf := isSSRFClass(class)

	var confirmed bool
	var confidence float64
	var verdict string
	switch {
	case ssrf:
		if t.nonScannerHTTP > 0 {
			confirmed, confidence = true, 0.85
			verdict = fmt.Sprintf("assessed non-scanner HTTP callback received (%d) — SSRF confirmed out-of-band", t.nonScannerHTTP)
		} else {
			verdict = "only DNS-only / scanner-origin / origin-unassessed interactions arrived — SSRF NOT confirmed (leads only; re-test with redirects disabled and require a non-scanner HTTP hit)"
		}
	default:
		switch {
		case t.nonScannerHTTP > 0:
			confirmed, confidence = true, 0.9
			verdict = fmt.Sprintf("non-scanner HTTP callback received (%d) — the target executed the payload out-of-band", t.nonScannerHTTP)
		case t.dns > 0:
			confirmed, confidence = true, 0.75
			verdict = fmt.Sprintf("DNS callback for the unique token received (%d) — the target's resolver looked up your callback, proving payload execution", t.dns)
		default:
			verdict = "only scanner-origin / origin-unassessed HTTP interactions arrived — NOT confirmed (a scanner-side hit is ambiguous); re-test so the callback is reached from the target"
		}
	}

	if !confirmed {
		// Measured failure mode (stability r2): after an ambiguous/declined
		// classification the model returned to polling instead of switching
		// proof strategies. The decline itself must carry the pivot.
		pivot := " Do NOT poll this token again — an ambiguous callback can never become proof. If the injected primitive runs in a server-side runtime/interpreter with a sleep-like capability (e.g. Java Thread.sleep), pivot NOW to verify_timing with a multi-second (>=3000 ms) server-native delay payload; otherwise drop this blind lead and move to the next-ranked surface."
		return tools.Result{
			Output:   fmt.Sprintf("Token %s: %d interaction(s), but %s.%s", token, t.total, verdict, pivot),
			Metadata: map[string]any{"oob_confirmed": false, "oob_hits": t.total},
		}
	}

	summary := fmt.Sprintf("Out-of-band %s proof for token %s: %s (interactions: %d non-scanner-HTTP, %d DNS, %d scanner-origin, %d unassessed).",
		class, token, verdict, t.nonScannerHTTP, t.dns, t.scannerHTTP, t.unassessedHTTP)
	if isExecutionOOBClass(class) {
		summary += fmt.Sprintf(" Execution attribution: %s with an exact callback-bearing payload.", executionPrimitive)
	}

	if l := a.ledger(); l != nil {
		h := l.Upsert(scanctx.Hypothesis{
			Title:      "Out-of-band confirmed " + class + " at " + endpoint,
			VulnClass:  class,
			Endpoint:   endpoint,
			Parameter:  parameter,
			Role:       role,
			Confidence: confidence,
			Status:     scanctx.HypothesisTesting,
			Origin:     "verify_oob",
			NextAction: "Report as " + class + " using the out-of-band callback as proof, then link the finding via add_hypothesis_evidence(kind=finding_ref).",
		})
		requestEvidence := "OOB token: " + token
		if isExecutionOOBClass(class) {
			requestEvidence += "; execution primitive: " + executionPrimitive + "; callback-bearing payload: " + truncateOOBEvidence(payloadEvidence, 2000)
		}
		l.AddEvidence(h.ID, scanctx.Evidence{
			Kind:       "exploit",
			Summary:    summary,
			Request:    requestEvidence,
			Response:   firstHitSummary(hits),
			Confidence: confidence,
			AgentID:    a.ledgerOrigin(),
		})
	}

	return tools.Result{
		Output:   summary + " Recorded in the ledger — report it and link the finding.",
		Metadata: map[string]any{"oob_confirmed": true, "oob_hits": t.total, "execution_primitive": executionPrimitive},
	}
}

func truncateOOBEvidence(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// firstHitSummary renders a compact description of the strongest interaction
// for ledger evidence.
func firstHitSummary(hits []oobsrv.Interaction) string {
	// Prefer a non-scanner HTTP hit, then DNS, then anything.
	pick := hits[0]
	for _, h := range hits {
		proto := strings.ToLower(strings.TrimSpace(h.Protocol))
		if (proto == "http" || proto == "https") && h.OriginAssessed && !h.ScannerOrigin {
			pick = h
			break
		}
	}
	return fmt.Sprintf("%s %s %s from %s at %s", strings.ToUpper(pick.Protocol), pick.Method, pick.Path, pick.RemoteAddr, pick.Time.Format("2006-01-02T15:04:05Z07:00"))
}

// normalizeBlindClass lower-cases and hyphenates a class label.
func normalizeBlindClass(s string) string {
	c := strings.ToLower(strings.TrimSpace(s))
	return strings.ReplaceAll(c, "_", "-")
}

// isSSRFClass reports whether a class should be held to the stricter SSRF
// (assessed-non-scanner-HTTP-only) verdict.
func isSSRFClass(c string) bool {
	return strings.Contains(c, "ssrf")
}
