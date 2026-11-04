package agent

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

// verify_authbypass confirms an authentication/authorization ENFORCEMENT bypass
// that identity-based checks (authz_matrix) cannot see: a protected route is
// properly denied on its canonical path when requested unauthenticated, but an
// equivalent path-shape variant (case fold, percent-encoding, a trailing
// segment or separator) reaches the same protected handler unauthenticated and
// is served. It varies the path shape with no credential at all, holding the
// identity anonymous — the complement of authz_matrix, which varies identity
// and holds the path fixed.
//
// The caller supplies a protected canonical route, not a prewritten payload.
// The verifier sends an unauthenticated baseline (which must be denied for a
// bypass to be possible) and a bounded, deterministic set of equivalent-path
// variants, also unauthenticated and without path normalization, confirming
// only on a deny→allow status flip whose body diverges from the denied
// baseline.
func (a *Agent) registerVerifyAuthBypassTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "verify_authbypass",
		Description: "Deterministically CONFIRM an authentication/authorization ENFORCEMENT bypass on a protected route. Give a url such as https://target/api/admin/users (or a ledger hypothesis_id) that is access-controlled (401/403) when requested WITHOUT credentials. It re-requests the canonical path unauthenticated as a denied baseline, then tries equivalent path-shape variants unauthenticated and without normalizing the path (case fold, percent-encoding, trailing slash/dot/matrix segment), and confirms only if a variant is SERVED (2xx) with a body that diverges from the denied baseline. On success it records the request/response differential in the ledger. Report as CWE-288 (medium; escalate to high only if the served body clearly exposes sensitive/admin data). Uses no scan credentials, honors rate limits, never follows redirects, and is disabled in passive mode. Use this for a path-variant bypass that authz_matrix (which varies identity, not path shape) cannot detect.",
		Parameters: []tools.Parameter{
			{Name: "url", Description: "Absolute URL or path of the protected canonical route (for example /api/admin/users). Supply this or hypothesis_id.", Required: false},
			{Name: "hypothesis_id", Description: "Ledger hypothesis carrying a protected route; used when url is absent.", Required: false},
		},
		Execute: a.verifyAuthBypassTool,
	})
}

func (a *Agent) verifyAuthBypassTool(args map[string]string) (tools.Result, error) {
	l := a.ledger()
	if l == nil {
		return tools.Result{Error: "ledger unavailable in this context"}, nil
	}
	if normalizeActivityMode(a.scanIntensity) == activityModePassive {
		return tools.Result{Error: "verify_authbypass issues live requests and is disabled in passive scan mode."}, nil
	}
	rawEP := strings.TrimSpace(args["url"])
	baseHint := ""
	if rawEP == "" {
		id := strings.TrimSpace(args["hypothesis_id"])
		if id == "" {
			return tools.Result{Error: "url or hypothesis_id is required"}, nil
		}
		h, ok := l.Get(id)
		if !ok {
			return tools.Result{Error: fmt.Sprintf("unknown hypothesis id %q", id)}, nil
		}
		rawEP, baseHint = strings.TrimSpace(h.Endpoint), strings.TrimSpace(h.Target)
	}
	absURL, err := a.resolveInjectionURL(rawEP, baseHint)
	if err != nil {
		return tools.Result{Error: "verify_authbypass: " + err.Error()}, nil
	}
	u, err := url.Parse(absURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return tools.Result{Error: "verify_authbypass: a valid HTTP(S) protected route is required"}, nil
	}
	if u.Path == "" || u.Path == "/" {
		return tools.Result{Error: "verify_authbypass: give the protected route path (for example /api/admin/users), not just the host"}, nil
	}
	if scopeguard.IsLocalOrListener(a.localGuard, u.Host) {
		return tools.Result{Error: fmt.Sprintf("verify_authbypass refused: %q resolves to the operator's own machine or local network, not the engagement target.", u.Host)}, nil
	}

	// Deliberately unauthenticated: SendRaw adds no per-scan session credentials
	// unless we pass them, and we never do here. The whole oracle is anonymous
	// canonical (denied) vs anonymous variant (served).
	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	canonicalURL := u.String()
	baseline, err := httpclient.SendRaw(httpclient.RawRequest{
		Method: "GET", URL: canonicalURL, FollowRedirects: false, TimeoutSec: 30,
	})
	if err != nil {
		return tools.Result{Error: fmt.Sprintf("verify_authbypass: canonical baseline request failed: %v", err)}, nil
	}
	denied, baselineNote := baselineIsDenied(baseline)
	if !denied {
		return tools.Result{
			Output:   fmt.Sprintf("Auth bypass NOT applicable at %s: the canonical path is %s unauthenticated, so it is not access-controlled and there is no enforcement to bypass. Do not report this as a finding.", u.EscapedPath(), baselineNote),
			Metadata: map[string]any{"authbypass_confirmed": false, "endpoint": u.EscapedPath(), "reason": "canonical_not_protected"},
		}, nil
	}

	canonicalPath := u.EscapedPath()
	query := ""
	if u.RawQuery != "" {
		query = "?" + u.RawQuery
	}
	origin := u.Scheme + "://" + u.Host

	// Catch-all fingerprint: some hosts (SPA shells, soft-404s) serve HTTP 200
	// with the same body for ANY path, so a bare deny→200 status flip would be a
	// false positive. Request a guaranteed-nonexistent sibling unauthenticated;
	// if it is also served, remember its body so a variant that merely returns
	// that same shell is not mistaken for a reached protected handler.
	catchAllNorm := ""
	softURL := origin + canonicalPath + "-xalgorix-nonexistent-" + strconv.FormatInt(time.Now().UnixNano(), 36) + query
	if soft, softErr := httpclient.SendRaw(httpclient.RawRequest{
		Method: "GET", URL: softURL, FollowRedirects: false, TimeoutSec: 30,
	}); softErr == nil && soft.StatusCode >= 200 && soft.StatusCode < 300 {
		catchAllNorm = normalizeBodyForDiff(string(soft.Body))
	}

	for _, variant := range authBypassVariants(canonicalPath) {
		if stop := a.injectionRateGate(); stop != "" {
			return tools.Result{Error: stop}, nil
		}
		variantURL := origin + variant + query
		probe, probeErr := httpclient.SendRaw(httpclient.RawRequest{
			Method: "GET", URL: variantURL, FollowRedirects: false, TimeoutSec: 30,
		})
		if probeErr != nil {
			// A single malformed variant should not abort the whole oracle.
			continue
		}
		if !authBypassVerdict(baseline, probe, catchAllNorm) {
			continue
		}

		endpoint := canonicalPath
		baselineDesc := fmt.Sprintf("unauthenticated GET %s → HTTP %d (%s)", canonicalPath, baseline.StatusCode, baselineNote)
		sensitive := bodyLooksSensitive(string(probe.Body))
		sev := "medium"
		sevGuidance := "Report as medium: unauthenticated access-control enforcement bypass (the protected handler is reachable via an equivalent path, but no sensitive data was observed in the served body)."
		if sensitive {
			sev = "high"
			sevGuidance = "Report as high: the served body exposes apparently sensitive/administrative data to an unauthenticated request."
		}
		confirm := fmt.Sprintf("Authentication/authorization enforcement bypass CONFIRMED at %s (CWE-288): the canonical path is denied unauthenticated (%s), but the equivalent variant %q is served unauthenticated with HTTP %d and a body that differs from the denied baseline.", endpoint, baselineNote, variant, probe.StatusCode)
		proof := fmt.Sprintf("Denied baseline: %s, %d-byte body.\nBypass variant: unauthenticated GET %s → HTTP %d, %d-byte body.\nServed response excerpt:\n%s",
			baselineDesc, baseline.BodyLen, variantURL, probe.StatusCode, probe.BodyLen, boundedText(string(probe.Body), 600))

		h := l.Upsert(scanctx.Hypothesis{
			Title:      "Auth enforcement bypass at " + endpoint,
			VulnClass:  "auth-bypass",
			Endpoint:   endpoint,
			Target:     baseURLOf(u),
			Baseline:   baselineDesc,
			Confidence: 0.9,
			Status:     scanctx.HypothesisTesting,
			Origin:     "verify_authbypass",
			NextAction: "Report the confirmed auth enforcement bypass as CWE-288 with the captured canonical-vs-variant differential as proof, then link the finding via add_hypothesis_evidence(kind=finding_ref).",
		})
		l.AddEvidence(h.ID, scanctx.Evidence{
			Kind: "exploit",
			// Source marks this as engine-written exploit evidence (Evidence.Source,
			// which the model's add_hypothesis_evidence can never set). It is what
			// makes ledgerVerifierProof treat this differential as authoritative
			// proof and what keeps the hypothesis from being auto-exhausted.
			Source:     "verify_authbypass",
			Summary:    confirm,
			Request:    "GET " + variantURL + "  (no credentials)",
			Response:   boundedText(string(probe.Body), 600),
			Confidence: 0.9,
			AgentID:    a.ledgerOrigin(),
		})
		// A deny→allow status flip across two spellings of the same route, both
		// unauthenticated, is a deterministic enforcement-bypass differential.
		// Mark it proven immediately so the finish gate keeps the scan alive
		// until this evidence is reported.
		l.SetStatus(h.ID, scanctx.HypothesisProven, "unauthenticated path-variant request reached a protected handler the canonical path denies")
		return tools.Result{
			Output: confirm + fmt.Sprintf(" Recorded the differential in ledger %s. %s Call report_vulnerability now with severity=%s, cwe_id=CWE-288, title=\"Authentication enforcement bypass\", target=%s, endpoint=%s, method=GET, verification_method=exploited, hypothesis_id=%s, and exploitation_proof copied from the captured differential below. Do not escalate impact beyond what the served body shows.\n\n%s",
				h.ID, sevGuidance, sev, baseURLOf(u), endpoint, h.ID, proof),
			Metadata: map[string]any{"authbypass_confirmed": true, "endpoint": endpoint, "hypothesis_id": h.ID, "variant": variant, "severity": sev},
		}, nil
	}

	return tools.Result{
		Output:   fmt.Sprintf("Auth bypass NOT confirmed at %s: the canonical path is denied unauthenticated (%s) and every equivalent path-shape variant was also denied. This is evidence the route enforces authentication consistently. Do not report this probe as a finding.", canonicalPath, baselineNote),
		Metadata: map[string]any{"authbypass_confirmed": false, "endpoint": canonicalPath, "reason": "enforcement_holds"},
	}, nil
}

// baselineIsDenied reports whether an unauthenticated response to the canonical
// route is a genuine access-control denial, so that a later deny→allow flip is
// meaningful. A 2xx means the route is simply public (nothing to bypass); a
// 404/405/5xx means we cannot establish that the route is protected here.
func baselineIsDenied(resp *httpclient.RawResponse) (bool, string) {
	switch code := resp.StatusCode; {
	case code == 401 || code == 403:
		return true, fmt.Sprintf("HTTP %d", code)
	case code >= 300 && code < 400:
		loc := strings.ToLower(resp.Header.Get("Location"))
		if loc != "" && (strings.Contains(loc, "login") || strings.Contains(loc, "signin") ||
			strings.Contains(loc, "sign-in") || strings.Contains(loc, "auth") || strings.Contains(loc, "sso")) {
			return true, fmt.Sprintf("HTTP %d redirect to login", code)
		}
		return false, fmt.Sprintf("HTTP %d redirect (not to login)", code)
	case code >= 200 && code < 300:
		return false, fmt.Sprintf("served HTTP %d", code)
	default:
		return false, fmt.Sprintf("HTTP %d (route not established as protected)", code)
	}
}

// authBypassVerdict confirms a bypass only on a deny→allow status flip whose
// served body diverges from both the denied baseline and (when the host serves
// a catch-all shell for nonexistent paths) that catch-all body. The caller has
// already established that the baseline is a denial, so here we require the
// variant to be served (2xx) with a non-trivial body that is neither the denial
// page nor the catch-all shell — a variant that merely returns one of those, or
// a 3xx/4xx/5xx, is not a bypass. catchAllNorm is already normalized (or "").
func authBypassVerdict(baseline, variant *httpclient.RawResponse, catchAllNorm string) bool {
	if variant == nil || baseline == nil {
		return false
	}
	if variant.StatusCode < 200 || variant.StatusCode >= 300 {
		return false
	}
	vb := normalizeBodyForDiff(string(variant.Body))
	if len(vb) < 16 {
		// An empty or near-empty 2xx (e.g. a 200 with no content) is too weak to
		// claim a protected handler was reached.
		return false
	}
	if vb == normalizeBodyForDiff(string(baseline.Body)) {
		return false
	}
	if catchAllNorm != "" && vb == catchAllNorm {
		// The host serves this same body for a path that cannot exist, so the 2xx
		// is a catch-all, not a reached protected handler.
		return false
	}
	return true
}

// authBypassVariants returns a bounded, deterministic set of equivalent-path
// spellings for a canonical path, deduped and excluding the canonical itself.
// These are path-shape equivalences (case, percent-encoding, trailing
// separators/segments) that some routers normalize before dispatch but some
// authentication middleware matches literally — the classic enforcement gap.
func authBypassVariants(path string) []string {
	if path == "" || path == "/" {
		return nil
	}
	seen := map[string]bool{path: true}
	var out []string
	add := func(v string) {
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	first := segs[0]
	rest := ""
	if len(segs) > 1 {
		rest = "/" + strings.Join(segs[1:], "/")
	}

	if first != "" {
		// Case folds of the first segment.
		add("/" + strings.ToUpper(first) + rest)                                  // /API
		add("/" + strings.ToUpper(first[:1]) + strings.ToLower(first[1:]) + rest) // /Api
		if len(first) > 1 {
			add("/" + strings.ToLower(first[:len(first)-1]) + strings.ToUpper(first[len(first)-1:]) + rest) // /apI
		}
		// Percent-encode the first byte of the first segment (e.g. a → %61).
		add("/%" + fmt.Sprintf("%02x", first[0]) + first[1:] + rest)
	}

	// Trailing separators / segments on the full path. Routers often collapse
	// these before dispatch; literal auth matchers often do not.
	trimmed := strings.TrimSuffix(path, "/")
	add(trimmed + "/")
	add(trimmed + "//")
	add(trimmed + "/.")
	add(trimmed + "/..;/")
	add(trimmed + ";/")
	add(trimmed + "%2f")
	add(trimmed + ".json")

	return out
}

// normalizeBodyForDiff lowercases and collapses whitespace so that cosmetic
// differences (dynamic nonces aside) do not read as divergence, while a
// genuinely different page does.
func normalizeBodyForDiff(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// bodyLooksSensitive is a conservative signal that a served body exposes
// administrative or personal data, used only to recommend escalating the
// reported severity from medium to high.
func bodyLooksSensitive(body string) bool {
	l := strings.ToLower(body)
	markers := []string{
		"\"email\"", "\"password\"", "\"token\"", "\"api_key\"", "\"apikey\"",
		"\"secret\"", "\"ssn\"", "\"role\":\"admin", "\"is_admin\"", "\"isadmin\"",
		"password_hash", "private_key", "-----begin",
	}
	for _, m := range markers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}
