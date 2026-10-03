// Package agent — verify_sqli.go implements verify_sqli: a deterministic
// error-based SQL-injection confirmer, the SQLi counterpart of verify_xss.
//
// scan_source_sinks / scan_source_routes / probe_hypothesis get the agent to a
// reachable route that a source SQLi sink flows into, but PROVING the injection
// still relied on the model hand-crafting a quote payload, reading the response,
// and recognizing a DBMS error — several turns of scarce budget for a class that
// black-box scanners already miss most. verify_sqli closes that loop in one
// call: it sends a benign baseline, a single-quote "broken" request (an odd
// quote count breaks the SQL syntax), and a doubled-quote "balanced" request
// (the quote is escaped, so a compatible injectable app parses it cleanly again),
// then reasons over the three responses:
//
//   - broken shows a DBMS error, baseline and balanced do not        → confirmed
//   - baseline ALREADY errors (errors regardless of input)            → NOT confirmed
//   - broken shows no DBMS error                                      → NOT confirmed
//
// The balanced request must recover before this tool confirms the error-based
// signature. If both quote variants fail, a validator or filter can explain the
// result; preserve the candidate for a different proof method. A clean baseline
// also rejects pages that display the same error regardless of input.
//
// On confirmation it records exploit-proven evidence in the shared ledger
// (mirroring verify_xss) and tells the agent to report it as High CWE-89; it
// does NOT auto-report. DBMS-error detection reuses reporting.LooksLikeSQLError
// so the confirmer and the reporting impact-gate share one definition.
//
// Safety: like probe_hypothesis it resolves the target host internally, so it
// ALWAYS scope-checks the resolved host with scopeguard.IsLocalOrListener and
// refuses the operator's own machine/listener, honors the scan's request-rate
// policy and cancellation, uses the scan's session auth, does not follow
// redirects, and is disabled in passive mode.
package agent

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func (a *Agent) registerVerifySQLiTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "verify_sqli",
		Description: "Deterministically CONFIRM error-based SQL injection on a live parameter (the SQLi counterpart of verify_xss). Give it a ledger hypothesis_id (a source-route/authenticated-endpoint hypothesis) OR a url, plus the parameter to test. It issues three scope-gated requests — a benign baseline, a single-quote payload that breaks SQL syntax, and a doubled-quote payload that re-balances it — and confirms injection when a DBMS error (You have an error in your SQL syntax, ORA-#####, SQLSTATE, PG/psql, SQLite, unclosed quotation mark) appears on the broken request but NOT on the benign baseline. On success it records exploit-proven evidence in the ledger; report it as High CWE-89 error-based SQLi (paste the DBMS error). Uses the scan session auth, does not follow redirects, disabled in passive mode. Reach for it the moment you hit a parameter that reflects a SQL error or that a source sink flows into.",
		Parameters: []tools.Parameter{
			{Name: "parameter", Description: "The query parameter to inject the quote into (e.g. uid, id, q). Required.", Required: true},
			{Name: "hypothesis_id", Description: "Optional ledger hypothesis id carrying an HTTP path (e.g. H-7). Its endpoint is used as the URL when 'url' is not given.", Required: false},
			{Name: "url", Description: "Optional absolute URL (scheme://host/path) or path to test. Overrides the hypothesis endpoint. One of url or hypothesis_id is required.", Required: false},
			{Name: "method", Description: "HTTP method (default GET). The injected parameter is placed in the query string.", Required: false},
			{Name: "base_value", Description: "Benign base value the parameter normally takes (default '1'). Payloads are base_value+\"'\" (broken) and base_value+\"''\" (balanced).", Required: false},
		},
		Execute: a.verifySQLiTool,
	})
}

func (a *Agent) verifySQLiTool(args map[string]string) (tools.Result, error) {
	l := a.ledger()
	if l == nil {
		return tools.Result{Error: "ledger unavailable in this context"}, nil
	}
	if normalizeActivityMode(a.scanIntensity) == activityModePassive {
		return tools.Result{Error: "verify_sqli issues live injection requests and is disabled in passive scan mode."}, nil
	}

	parameter := strings.TrimSpace(args["parameter"])
	if parameter == "" {
		return tools.Result{Error: "parameter is required — name the query parameter to test (e.g. uid, id, q)."}, nil
	}

	// Resolve the URL to test: explicit url wins, else the hypothesis endpoint.
	rawEP := strings.TrimSpace(args["url"])
	baseHint := ""
	if rawEP == "" {
		id := strings.TrimSpace(args["hypothesis_id"])
		if id == "" {
			return tools.Result{Error: "one of url or hypothesis_id is required — pass a url to test, or a ledger hypothesis id carrying an HTTP path."}, nil
		}
		h, ok := l.Get(id)
		if !ok {
			return tools.Result{Error: fmt.Sprintf("unknown hypothesis id %q — use read_ledger to list ids", id)}, nil
		}
		rawEP = strings.TrimSpace(h.Endpoint)
		baseHint = strings.TrimSpace(h.Target)
	}

	absURL, err := a.resolveInjectionURL(rawEP, baseHint)
	if err != nil {
		return tools.Result{Error: "verify_sqli: " + err.Error()}, nil
	}
	u, perr := url.Parse(absURL)
	if perr != nil || u.Host == "" {
		return tools.Result{Error: fmt.Sprintf("verify_sqli: could not form a valid URL from %q", absURL)}, nil
	}

	// PRIMARY scope protection: the loop gate can't see this internally-resolved
	// host, so refuse the operator's own machine/listener here.
	if scopeguard.IsLocalOrListener(a.localGuard, u.Host) {
		return tools.Result{Error: fmt.Sprintf("verify_sqli refused: %q resolves to the operator's own machine or local network, not the engagement target.", u.Host)}, nil
	}

	method := strings.ToUpper(strings.TrimSpace(args["method"]))
	if method == "" {
		method = "GET"
	}
	baseVal := strings.TrimSpace(args["base_value"])
	if baseVal == "" {
		baseVal = "1"
	}

	headers := a.probeAuthHeaders()
	authed := len(headers) > 0

	// Three payloads: benign baseline, single-quote (breaks syntax), doubled-quote
	// (re-balances it). A real error-based injection errors on the broken one and
	// stays clean on the baseline.
	baselineURL, e1 := withQueryParam(u, parameter, baseVal)
	brokenURL, e2 := withQueryParam(u, parameter, baseVal+"'")
	balancedURL, e3 := withQueryParam(u, parameter, baseVal+"''")
	if e1 != nil || e2 != nil || e3 != nil {
		return tools.Result{Error: "verify_sqli: could not build injection URLs for parameter " + parameter}, nil
	}

	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	baselineBody, _, bErr := a.sendInjectionProbe(method, baselineURL, headers)
	if bErr != nil {
		return tools.Result{Error: fmt.Sprintf("verify_sqli: baseline request failed: %v", bErr)}, nil
	}
	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	brokenBody, brokenReqLine, kErr := a.sendInjectionProbe(method, brokenURL, headers)
	if kErr != nil {
		return tools.Result{Error: fmt.Sprintf("verify_sqli: single-quote request failed: %v", kErr)}, nil
	}
	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	balancedBody, _, lErr := a.sendInjectionProbe(method, balancedURL, headers)
	if lErr != nil {
		return tools.Result{Error: fmt.Sprintf("verify_sqli: doubled-quote request failed: %v", lErr)}, nil
	}

	confirmed, confidence, note := sqliErrorVerdict(baselineBody, brokenBody, balancedBody)
	endpoint := u.EscapedPath()
	authTag := ""
	if authed {
		authTag = " [authenticated]"
	}

	if !confirmed {
		return tools.Result{
			Output:   fmt.Sprintf("SQLi NOT confirmed on %q at %s%s: %s", parameter, endpoint, authTag, note),
			Metadata: map[string]any{"sqli_confirmed": false, "parameter": parameter, "endpoint": endpoint},
		}, nil
	}

	brokenExcerpt := boundedText(brokenBody, 600)
	confirm := fmt.Sprintf("Error-based SQL injection CONFIRMED on parameter %q at %s%s: a single-quote payload provoked a DBMS error absent from the benign baseline — the input reaches a SQL query unsanitized (CWE-89).", parameter, endpoint, authTag)
	proof := fmt.Sprintf("Baseline  %s=%s   → no SQL error.\nBroken    %s=%s'  → DBMS error:\n%s\nBalanced  %s=%s'' → %s\n%s",
		parameter, baseVal,
		parameter, baseVal, brokenExcerpt,
		parameter, baseVal, ternary(reporting.LooksLikeSQLError(balancedBody), "still errored", "no SQL error (quote re-balanced)"),
		note)

	h := l.Upsert(scanctx.Hypothesis{
		Title:      "Error-based SQL injection at " + endpoint,
		VulnClass:  "sqli",
		Endpoint:   endpoint,
		Parameter:  parameter,
		Target:     baseURLOf(u),
		Confidence: confidence,
		Status:     scanctx.HypothesisTesting,
		Origin:     "verify_sqli",
		NextAction: "Report as High SQL injection (CWE-89, CVSS vector with C:H) using the DBMS error as proof, then link the finding via add_hypothesis_evidence(kind=finding_ref).",
	})
	l.AddEvidence(h.ID, scanctx.Evidence{
		Kind:       "exploit",
		Summary:    confirm,
		Request:    brokenReqLine,
		Response:   brokenExcerpt,
		Confidence: confidence,
		AgentID:    a.ledgerOrigin(),
	})

	return tools.Result{
		Output:   confirm + fmt.Sprintf(" Recorded exploit-proven in the ledger (%s, confidence %.2f) — report it as High CWE-89 and link the finding.\n\n%s", h.ID, confidence, proof),
		Metadata: map[string]any{"sqli_confirmed": true, "parameter": parameter, "endpoint": endpoint, "hypothesis_id": h.ID, "confidence": confidence},
	}, nil
}

// sqliErrorVerdict decides error-based SQLi from the three response bodies. The
// core proof is the baseline→broken transition: a DBMS error that appears when a
// single quote is injected but is ABSENT on the benign baseline. The balanced
// (doubled-quote) response must recover to distinguish the classic break/recover
// signature from a validator or WAF that rejects any quote. A baseline that
// already errors is rejected outright: the endpoint errors regardless of input,
// so the error is not controlled by the injected quote.
func sqliErrorVerdict(baseline, broken, balanced string) (confirmed bool, confidence float64, note string) {
	if !reporting.LooksLikeSQLError(broken) {
		return false, 0, "the single-quote payload produced no DBMS error — not error-based SQL-injectable here (the parameter may be numeric-cast/validated, or the injection is blind; for blind SQLi use a time-based payload or an OOB callback via verify_oob)."
	}
	if reporting.LooksLikeSQLError(baseline) {
		return false, 0, "the benign baseline ALREADY shows a DBMS error, so the endpoint errors regardless of input — the error is not controlled by the injected quote (not a proven injection point)."
	}
	if reporting.LooksLikeSQLError(balanced) {
		return false, 0, "the balanced request also errored. Quote rejection, validation, or a filtering layer can produce this pattern without SQL injection; no break/recover signature was reproduced. Preserve the candidate and test a separate boolean, timing, or data-extraction control."
	}
	return true, 0.95, "the DBMS error appeared only on the single-quote request and vanished when the quote was balanced — the classic error-based SQL-injection signature."
}

// resolveInjectionURL turns a raw endpoint (a url arg or a hypothesis endpoint) into
// an absolute URL to test. It rejects source-location (file:line) endpoints,
// uses an absolute URL as-is, and otherwise joins a path against the base hint
// (the hypothesis target) or the scan target.
func (a *Agent) resolveInjectionURL(rawEP, baseHint string) (string, error) {
	ep := strings.TrimSpace(rawEP)
	if ep == "" {
		return "", fmt.Errorf("no url/endpoint to test")
	}
	if looksLikeSourceLocation(ep) {
		return "", fmt.Errorf("endpoint %q is a source location (file:line), not an HTTP path — pass a url or a source-route hypothesis, or run scan_source_routes first", ep)
	}
	if strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://") {
		return ep, nil
	}
	if !strings.HasPrefix(ep, "/") {
		ep = "/" + ep
	}
	base := strings.TrimSpace(baseHint)
	if base == "" {
		base = a.primaryTargetURL()
	}
	if base == "" {
		return "", fmt.Errorf("no base URL to resolve path %q — pass an absolute url or ensure the scan has a target", ep)
	}
	base = normalizeBaseURL(base)
	bu, err := url.Parse(base)
	if err != nil || bu.Host == "" {
		return "", fmt.Errorf("invalid base URL %q", base)
	}
	ref, err := url.Parse(ep)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint path %q", ep)
	}
	return bu.ResolveReference(ref).String(), nil
}

// injectionRateGate applies the scan's request-rate delay and reports a stop
// reason if the scan is shutting down, so the three probes honor rate policy and
// cancellation exactly as probe_hypothesis does.
func (a *Agent) injectionRateGate() string {
	if a.ctx != nil && a.ctx.Err() != nil {
		return "injection verifier: scan is shutting down"
	}
	if a.scanCtx != nil {
		if d := a.scanCtx.RequestRatePolicy().Delay(); d > 0 {
			timer := time.NewTimer(d)
			defer timer.Stop()
			var done <-chan struct{}
			if a.ctx != nil {
				done = a.ctx.Done()
			}
			select {
			case <-timer.C:
			case <-done:
				return "injection verifier: scan is shutting down"
			}
		}
	}
	return ""
}

// sendInjectionProbe issues one scope-agnostic request (the host was scope-checked by
// the caller) and returns the response body as a string plus the request line.
func (a *Agent) sendInjectionProbe(method, rawURL string, headers map[string]string) (body, reqLine string, err error) {
	reqLine = method + " " + rawURL
	resp, e := httpclient.SendRaw(httpclient.RawRequest{
		Method:          method,
		URL:             rawURL,
		Headers:         headers,
		FollowRedirects: false,
		TimeoutSec:      30,
	})
	if e != nil {
		return "", reqLine, e
	}
	return string(resp.Body), reqLine, nil
}

// withQueryParam returns rawURL with the query parameter set to value.
func withQueryParam(u *url.URL, param, value string) (string, error) {
	cp := *u
	q := cp.Query()
	q.Set(param, value)
	cp.RawQuery = q.Encode()
	return cp.String(), nil
}

// baseURLOf returns scheme://host for a parsed URL.
func baseURLOf(u *url.URL) string {
	if u == nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// boundedText trims text to max runes with an ellipsis, for compact ledger proof.
func boundedText(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// ternary returns a when cond else b (small readability helper for proof text).
func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
