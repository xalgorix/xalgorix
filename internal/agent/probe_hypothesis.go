// Package agent — probe_hypothesis.go implements probe_hypothesis: the third
// part of the source-to-runtime bridge. scan_source_sinks finds the dangerous
// code, scan_source_routes gives it a reachable HTTP path, and probe_hypothesis
// takes that path and actually TOUCHES the live target — issuing one scope-gated
// baseline request and recording the response as ledger evidence.
//
// This closes the loop: a seeded source→route hypothesis stops being a guess and
// becomes a confirmed-reachable (2xx/redirect/protected/5xx) or blocked (404 /
// connection failure) lead, with the real response attached as evidence and the
// status/confidence nudged accordingly — so the evidence-driven scheduler works
// the routes that actually exist first.
//
// Safety: the tool resolves the target host from the hypothesis/scan itself, so
// the agent-loop scope gate (which keys off tool args) cannot see it. Therefore
// this tool ALWAYS scope-checks the resolved host with scopeguard.IsLocalOrListener
// and refuses the operator's own machine/listener, exactly as authz_matrix does
// for defense-in-depth. It reuses httpclient.SendRaw (the same scope-agnostic
// request path authz_matrix uses), honors the scan's request-rate policy and
// cancellation, does not follow redirects, and is disabled in passive mode.
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
)

func (a *Agent) registerProbeHypothesisTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "probe_hypothesis",
		Description: "Issue ONE scope-gated baseline HTTP request against the LIVE target for a ledger hypothesis that carries a real HTTP path (e.g. a source-route hypothesis from scan_source_routes, or an ingested/authenticated endpoint), and record the response as evidence. Turns a seeded path into a confirmed lead: a live 2xx raises confidence and moves it to testing; 401/403 flags it as an authz_matrix target; a 404/connection failure marks it blocked. Uses the scan's session auth automatically so authenticated routes are probed authenticated, and does not follow redirects (a 3xx to /login is itself a signal). Use it to triage which seeded routes actually exist before investing in exploitation. Skips hypotheses whose endpoint is a source location (file:line) rather than an HTTP path.",
		Parameters: []tools.Parameter{
			{Name: "hypothesis_id", Description: "The ledger hypothesis id to probe (e.g. H-7). Must carry an HTTP path endpoint (not a file:line source location).", Required: true},
			{Name: "base_url", Description: "Optional base URL (scheme://host) to resolve a bare path against. Defaults to the hypothesis's target host, then the scan target.", Required: false},
			{Name: "method", Description: "HTTP method for the baseline request (default GET).", Required: false},
		},
		Execute: a.probeHypothesisTool,
	})
}

func (a *Agent) probeHypothesisTool(args map[string]string) (tools.Result, error) {
	l := a.ledger()
	if l == nil {
		return tools.Result{Error: "ledger unavailable in this context"}, nil
	}
	// An active probe is disabled in passive scan mode.
	if normalizeActivityMode(a.scanIntensity) == activityModePassive {
		return tools.Result{Error: "probe_hypothesis issues a live request and is disabled in passive scan mode."}, nil
	}

	id := strings.TrimSpace(args["hypothesis_id"])
	if id == "" {
		return tools.Result{Error: "hypothesis_id is required"}, nil
	}
	h, ok := l.Get(id)
	if !ok {
		return tools.Result{Error: fmt.Sprintf("unknown hypothesis id %q — use read_ledger to list ids", id)}, nil
	}

	absURL, err := a.resolveProbeURL(h, strings.TrimSpace(args["base_url"]))
	if err != nil {
		return tools.Result{Error: "probe_hypothesis: " + err.Error()}, nil
	}
	u, perr := url.Parse(absURL)
	if perr != nil || u.Host == "" {
		return tools.Result{Error: fmt.Sprintf("probe_hypothesis: could not form a valid URL from %q", absURL)}, nil
	}

	// PRIMARY scope protection: the loop gate can't see this internally-resolved
	// host, so refuse the operator's own machine/listener here.
	if scopeguard.IsLocalOrListener(a.localGuard, u.Host) {
		return tools.Result{Error: fmt.Sprintf("probe_hypothesis refused: %q resolves to the operator's own machine or local network, not the engagement target.", u.Host)}, nil
	}

	if a.ctx != nil && a.ctx.Err() != nil {
		return tools.Result{Error: "probe_hypothesis: scan is shutting down"}, nil
	}
	if a.scanCtx != nil {
		if d := a.scanCtx.RequestRatePolicy().Delay(); d > 0 {
			time.Sleep(d)
		}
	}

	method := strings.ToUpper(strings.TrimSpace(args["method"]))
	if method == "" {
		method = "GET"
	}
	headers := a.probeAuthHeaders()
	authed := len(headers) > 0
	reqLine := method + " " + u.String()

	resp, sErr := httpclient.SendRaw(httpclient.RawRequest{
		Method:          method,
		URL:             u.String(),
		Headers:         headers,
		FollowRedirects: false, // a 3xx→login is itself a signal, not something to mask
		TimeoutSec:      30,
	})
	if sErr != nil {
		l.AddEvidence(id, scanctx.Evidence{
			Kind:    "probe",
			Summary: "Baseline probe could not connect: " + sErr.Error(),
			Request: reqLine,
			AgentID: a.ledgerOrigin(),
		})
		l.SetStatus(id, scanctx.HypothesisBlocked, "Route did not respond ("+sErr.Error()+"). Confirm the target host / base_url, or the route may not be deployed here.")
		return tools.Result{Output: fmt.Sprintf("Probed %s → connection error: %v. Marked %s blocked.", reqLine, sErr, id)}, nil
	}

	summary, status, nextAction, conf := interpretProbe(resp, authed)
	l.AddEvidence(id, scanctx.Evidence{
		Kind:       "probe",
		Summary:    summary,
		Request:    reqLine,
		Response:   probeResponseEvidence(resp),
		Confidence: conf,
		AgentID:    a.ledgerOrigin(),
	})
	if status != "" {
		l.SetStatus(id, status, nextAction)
	}
	got, _ := l.Get(id)

	authTag := ""
	if authed {
		authTag = " [authenticated]"
	}
	return tools.Result{
		Output: fmt.Sprintf("Probed %s%s → %s (%d-byte body). %s\nHypothesis %s is now [%s], confidence %.2f. Next: %s",
			reqLine, authTag, resp.Status, resp.BodyLen, summary, id, got.Status, got.Confidence, nextAction),
		Metadata: map[string]any{"hypothesis_id": id, "status_code": resp.StatusCode, "http_status": resp.Status, "authenticated": authed},
	}, nil
}

// resolveProbeURL turns a hypothesis endpoint into an absolute URL to probe. It
// rejects source-location (file:line) endpoints, uses an absolute endpoint
// as-is, and otherwise joins a path against the base URL (explicit override →
// hypothesis Target host → scan target).
func (a *Agent) resolveProbeURL(h scanctx.Hypothesis, baseOverride string) (string, error) {
	ep := strings.TrimSpace(h.Endpoint)
	if ep == "" {
		return "", fmt.Errorf("hypothesis %s has no endpoint to probe", h.ID)
	}
	if h.Origin == "source-sink" || looksLikeSourceLocation(ep) {
		return "", fmt.Errorf("hypothesis %s endpoint %q is a source location (file:line), not an HTTP path — probe a source-route or authenticated-endpoint hypothesis, or run scan_source_routes first", h.ID, ep)
	}
	if strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://") {
		return ep, nil
	}
	if !strings.HasPrefix(ep, "/") {
		ep = "/" + ep
	}

	base := strings.TrimSpace(baseOverride)
	if base == "" && strings.TrimSpace(h.Target) != "" {
		base = strings.TrimSpace(h.Target)
	}
	if base == "" {
		base = a.primaryTargetURL()
	}
	if base == "" {
		return "", fmt.Errorf("no base URL to resolve path %q — pass base_url (scheme://host) or ensure the scan has a target", ep)
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

// primaryTargetURL returns the scan's first target normalized to a base URL, or
// "" when Run has not recorded a target.
func (a *Agent) primaryTargetURL() string {
	for _, t := range a.targets {
		if t = strings.TrimSpace(t); t != "" {
			return normalizeBaseURL(t)
		}
	}
	return ""
}

// probeAuthHeaders resolves the scan's role-A session headers (operator-configured
// target auth first, else an ingested session), so an authenticated route is
// probed authenticated. Empty when the scan has no session.
func (a *Agent) probeAuthHeaders() map[string]string {
	if hdrs := httpclient.ParseAuthHeaders(a.targetAuth); len(hdrs) > 0 {
		return hdrs
	}
	return a.sessionAuthHeaders()
}

// normalizeBaseURL ensures a base URL carries a scheme (defaulting to https),
// matching how http_request/authz_matrix/SendRaw treat schemeless targets.
func normalizeBaseURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return s
}

// looksLikeSourceLocation reports whether an endpoint is a "file:line" source
// location (as seeded by scan_source_sinks) rather than an HTTP path/URL.
func looksLikeSourceLocation(ep string) bool {
	if strings.HasPrefix(ep, "/") || strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://") {
		return false
	}
	// e.g. "handlers.py:42": a trailing ":<digits>" with no path-separator prefix.
	if i := strings.LastIndex(ep, ":"); i > 0 && i < len(ep)-1 {
		for _, c := range ep[i+1:] {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// interpretProbe classifies a baseline response into an evidence summary, a
// status transition, a next action, and an evidence confidence. AddEvidence
// only raises confidence, so a 404 passes conf 0 and relies on the blocked
// status transition to deprioritize the hypothesis.
func interpretProbe(resp *httpclient.RawResponse, authed bool) (summary string, status scanctx.HypothesisStatus, nextAction string, conf float64) {
	authNote := ""
	if authed {
		authNote = " (authenticated)"
	}
	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		return fmt.Sprintf("Live%s: %s, %d-byte body — route is reachable and serves content.", authNote, resp.Status, resp.BodyLen),
			scanctx.HypothesisTesting,
			"Route confirmed live (2xx). Build the class-specific payload and attempt exploitation; for object/action endpoints use authz_matrix across role A/B/anonymous.",
			0.6
	case code == 401 || code == 403:
		return fmt.Sprintf("Access-controlled%s: %s — endpoint exists but is protected.", authNote, resp.Status),
			scanctx.HypothesisTesting,
			"Endpoint exists but is access-controlled — prime target for authz_matrix (vary identity: role A vs role B vs anonymous) and verify_authbypass (vary the path shape unauthenticated: case fold, encoding, trailing segment — e.g. /Api vs /api).",
			0.5
	case code == 404 || code == 410:
		return fmt.Sprintf("Not found: %s — route not deployed at this path on the live target.", resp.Status),
			scanctx.HypothesisBlocked,
			"Route returned 404/410 — it may not be deployed here, the base path differs, or it needs path parameters. Verify the route or pass base_url.",
			0
	case code == 405:
		return fmt.Sprintf("Method not allowed: %s — endpoint exists but rejects this method.", resp.Status),
			scanctx.HypothesisTesting,
			"Endpoint exists but rejects this method; retry with the route's declared method (POST/PUT/PATCH).",
			0.45
	case code >= 500:
		return fmt.Sprintf("Server error%s: %s — handler is reachable and erroring.", authNote, resp.Status),
			scanctx.HypothesisTesting,
			"Server error (5xx) — the handler is reachable and failing; probe for injection (the error may leak a stack trace or query).",
			0.55
	case code >= 300 && code < 400:
		return fmt.Sprintf("Redirect: %s → %s.", resp.Status, resp.Header.Get("Location")),
			scanctx.HypothesisTesting,
			"Redirects (often to login/SSO). If unauthenticated, register a session (ingest_har) or configure target auth, then re-probe; the redirect target itself may be an open-redirect sink.",
			0.4
	default:
		return fmt.Sprintf("Response: %s (%d-byte body).", resp.Status, resp.BodyLen),
			scanctx.HypothesisTesting,
			"Endpoint responded; analyze the response and craft the class-specific test.",
			0.4
	}
}

// probeResponseEvidence renders a compact response record (status line, a few
// telling headers, a bounded body slice) for the ledger. The ledger re-bounds
// the stored string, so this only needs to stay reasonable.
func probeResponseEvidence(resp *httpclient.RawResponse) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", resp.Proto, resp.Status)
	for _, name := range []string{"Location", "Content-Type", "WWW-Authenticate", "Server", "Set-Cookie"} {
		if v := resp.Header.Get(name); v != "" {
			fmt.Fprintf(&b, "%s: %s\n", name, v)
		}
	}
	if body := strings.TrimSpace(string(resp.Body)); body != "" {
		if len(body) > 800 {
			body = body[:800] + "…"
		}
		b.WriteString("\n")
		b.WriteString(body)
	}
	return b.String()
}
