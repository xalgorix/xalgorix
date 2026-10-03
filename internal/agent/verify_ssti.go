// Package agent — verify_ssti.go implements verify_ssti: a deterministic
// server-side template injection confirmer, the SSTI sibling of verify_sqli.
//
// The source-to-runtime bridge seeds and correlates a template sink to its
// route, but PROVING the injection relied on the model hand-crafting a {{7*7}}
// payload, reading the response, and recognizing the evaluated product — and a
// benchmark run showed it frequently fails to within budget (0 findings on the
// whitebox-ssti challenge even with the route correlated). verify_ssti closes
// that loop in one call: it sends a benign baseline plus template payloads whose
// operands are RANDOMIZED — {{a*b}} (Jinja2/Twig/Nunjucks) and ${a*b}
// (Freemarker/JSP-EL/Velocity) — and confirms SSTI when the computed PRODUCT
// appears in the probe response but NOT in the baseline. A reflected-but-not-
// evaluated app echoes the literal "{{a*b}}" (which contains a and b, never
// their product), so the product's appearance is proof the engine evaluated the
// expression. Random operands make a coincidental product match astronomically
// unlikely, and the baseline-absence check rejects pages that happen to contain
// the number for unrelated reasons.
//
// On confirmation it records exploit-proven evidence in the shared ledger
// (mirroring verify_sqli/verify_xss) and tells the agent to report it as High
// CWE-1336; it does NOT auto-report. Safety: it resolves the target host
// internally and therefore always scope-checks it (refusing the operator's own
// machine/listener), uses the scan's session auth, does not follow redirects,
// honors the request-rate policy and cancellation, and is disabled in passive
// mode. It reuses the shared injection-probe helpers (resolveInjectionURL,
// sendInjectionProbe, injectionRateGate, withQueryParam).
package agent

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

func (a *Agent) registerVerifySSTITool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "verify_ssti",
		Description: "Deterministically CONFIRM server-side template injection on a live parameter (the SSTI sibling of verify_sqli). Give it a ledger hypothesis_id (a source-route/authenticated-endpoint hypothesis) OR a url, plus the parameter to test. It issues a benign baseline plus template payloads with RANDOMIZED operands — {{a*b}} (Jinja2/Twig/Nunjucks) and ${a*b} (Freemarker/JSP-EL/Velocity) — and confirms injection when the computed product appears in the probe response but NOT the baseline (a reflected-but-not-evaluated app echoes the literal {{a*b}}, never its product). On success it records exploit-proven evidence in the ledger; report it as High CWE-1336 SSTI (paste the evaluated arithmetic) and pivot toward RCE via the engine's gadget. Uses the scan session auth, does not follow redirects, disabled in passive mode. Reach for it the moment you hit a parameter that a template sink flows into or that reflects into rendered markup.",
		Parameters: []tools.Parameter{
			{Name: "parameter", Description: "The query parameter to inject the template expression into (e.g. name, tpl, q). Required.", Required: true},
			{Name: "hypothesis_id", Description: "Optional ledger hypothesis id carrying an HTTP path (e.g. H-7). Its endpoint is used as the URL when 'url' is not given.", Required: false},
			{Name: "url", Description: "Optional absolute URL (scheme://host/path) or path to test. Overrides the hypothesis endpoint. One of url or hypothesis_id is required.", Required: false},
			{Name: "method", Description: "HTTP method (default GET). The payload is placed in the query string.", Required: false},
			{Name: "base_value", Description: "Benign base value for the baseline request (default 'xalg'). The template payloads are independent of it.", Required: false},
		},
		Execute: a.verifySSTITool,
	})
}

func (a *Agent) verifySSTITool(args map[string]string) (tools.Result, error) {
	l := a.ledger()
	if l == nil {
		return tools.Result{Error: "ledger unavailable in this context"}, nil
	}
	if normalizeActivityMode(a.scanIntensity) == activityModePassive {
		return tools.Result{Error: "verify_ssti issues live injection requests and is disabled in passive scan mode."}, nil
	}

	parameter := strings.TrimSpace(args["parameter"])
	if parameter == "" {
		return tools.Result{Error: "parameter is required — name the query parameter to test (e.g. name, tpl, q)."}, nil
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
		return tools.Result{Error: "verify_ssti: " + err.Error()}, nil
	}
	u, perr := url.Parse(absURL)
	if perr != nil || u.Host == "" {
		return tools.Result{Error: fmt.Sprintf("verify_ssti: could not form a valid URL from %q", absURL)}, nil
	}

	// PRIMARY scope protection: the loop gate can't see this internally-resolved
	// host, so refuse the operator's own machine/listener here.
	if scopeguard.IsLocalOrListener(a.localGuard, u.Host) {
		return tools.Result{Error: fmt.Sprintf("verify_ssti refused: %q resolves to the operator's own machine or local network, not the engagement target.", u.Host)}, nil
	}

	method := strings.ToUpper(strings.TrimSpace(args["method"]))
	if method == "" {
		method = "GET"
	}
	baseVal := strings.TrimSpace(args["base_value"])
	if baseVal == "" {
		baseVal = "xalg"
	}

	headers := a.probeAuthHeaders()
	authed := len(headers) > 0

	// Randomized operands: a distinctive 5–6 digit product that a literal echo of
	// the payload cannot contain, and that is vanishingly unlikely to appear by
	// chance.
	opA := randRange(211, 989)
	opB := randRange(211, 989)
	product := strconv.Itoa(opA * opB)

	baselineURL, e0 := withQueryParam(u, parameter, baseVal)
	if e0 != nil {
		return tools.Result{Error: "verify_ssti: could not build the baseline URL for parameter " + parameter}, nil
	}
	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	baselineBody, _, bErr := a.sendInjectionProbe(method, baselineURL, headers)
	if bErr != nil {
		return tools.Result{Error: fmt.Sprintf("verify_ssti: baseline request failed: %v", bErr)}, nil
	}

	// Try each template syntax; confirm on the first that evaluates to the product.
	probes := []struct{ family, payload string }{
		{"Jinja2/Twig/Nunjucks", fmt.Sprintf("{{%d*%d}}", opA, opB)},
		{"Freemarker/JSP-EL/Velocity", fmt.Sprintf("${%d*%d}", opA, opB)},
	}
	lastNote := ""
	for _, p := range probes {
		if stop := a.injectionRateGate(); stop != "" {
			return tools.Result{Error: stop}, nil
		}
		probeURL, e := withQueryParam(u, parameter, p.payload)
		if e != nil {
			continue
		}
		probeBody, probeReqLine, pErr := a.sendInjectionProbe(method, probeURL, headers)
		if pErr != nil {
			return tools.Result{Error: fmt.Sprintf("verify_ssti: %s probe request failed: %v", p.family, pErr)}, nil
		}
		confirmed, note := sstiEvalVerdict(baselineBody, probeBody, product)
		lastNote = note
		if !confirmed {
			continue
		}

		endpoint := u.EscapedPath()
		authTag := ""
		if authed {
			authTag = " [authenticated]"
		}
		excerpt := boundedText(probeBody, 600)
		confirm := fmt.Sprintf("Server-side template injection CONFIRMED on parameter %q at %s%s (%s engine): the payload %s was evaluated server-side to %s — the template engine executed the injected expression (CWE-1336).",
			parameter, endpoint, authTag, p.family, p.payload, product)
		proof := fmt.Sprintf("Baseline %s=%s → product %s absent.\nProbe    %s=%s → response contains the evaluated product %s:\n%s\n%s",
			parameter, baseVal, product, parameter, p.payload, product, excerpt, note)

		h := l.Upsert(scanctx.Hypothesis{
			Title:      "Server-side template injection at " + endpoint,
			VulnClass:  "ssti",
			Endpoint:   endpoint,
			Parameter:  parameter,
			Target:     baseURLOf(u),
			Confidence: 0.9,
			Status:     scanctx.HypothesisTesting,
			Origin:     "verify_ssti",
			NextAction: "Report as High server-side template injection (CWE-1336) using the evaluated arithmetic as proof, then escalate toward RCE via the engine's sandbox-escape gadget; link the finding via add_hypothesis_evidence(kind=finding_ref).",
		})
		l.AddEvidence(h.ID, scanctx.Evidence{
			Kind:       "exploit",
			Summary:    confirm,
			Request:    probeReqLine,
			Response:   excerpt,
			Confidence: 0.9,
			AgentID:    a.ledgerOrigin(),
		})

		return tools.Result{
			Output:   confirm + fmt.Sprintf(" Recorded exploit-proven in the ledger (%s) — report it as High CWE-1336 and link the finding.\n\n%s", h.ID, proof),
			Metadata: map[string]any{"ssti_confirmed": true, "parameter": parameter, "endpoint": endpoint, "engine": p.family, "hypothesis_id": h.ID},
		}, nil
	}

	if lastNote == "" {
		lastNote = "neither {{a*b}} nor ${a*b} was evaluated to its product."
	}
	return tools.Result{
		Output:   fmt.Sprintf("SSTI NOT confirmed on %q at %s: %s The parameter may be reflected literally or sanitized, or use a different template syntax. If the value is reflected into HTML, try verify_xss for client-side execution.", parameter, u.EscapedPath(), lastNote),
		Metadata: map[string]any{"ssti_confirmed": false, "parameter": parameter},
	}, nil
}

// sstiEvalVerdict decides SSTI from the baseline and template-probe responses.
// It confirms only when the probe response contains the ARITHMETIC PRODUCT of the
// injected expression (proving the engine evaluated it) while the benign baseline
// does not — a reflected-but-not-evaluated app echoes the literal "{{a*b}}",
// which contains a and b but never their product. A product that also appears in
// the baseline is treated as a coincidental match and rejected.
func sstiEvalVerdict(baseline, probe, product string) (confirmed bool, note string) {
	if strings.TrimSpace(product) == "" {
		return false, "no product to check"
	}
	if !strings.Contains(probe, product) {
		return false, "the injected arithmetic expression was not evaluated (its product did not appear in the response)."
	}
	if strings.Contains(baseline, product) {
		return false, "the product also appears in the benign baseline, so its presence is not caused by template evaluation (coincidental match)."
	}
	return true, "the product appears only in the injected response — the template engine evaluated the expression, proving SSTI."
}

// randRange returns a cryptographically-random int in [min, max). It falls back
// to min on any error or when the range is empty.
func randRange(min, max int) int {
	if max <= min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}
