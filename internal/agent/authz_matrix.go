// Package agent — authz_matrix.go implements the multi-role authorization
// matrix: replay one request across every configured identity (primary session
// "role A", a second account "role B", and anonymous) and report the
// access-control differential.
//
// This is the core primitive for the classes autonomous scanners are weakest
// at — IDOR/BOLA (horizontal), BFLA/privilege escalation and auth bypass
// (vertical). Instead of asking the model to eyeball whether a request "looks
// authorized", it deterministically sends the SAME request as each identity and
// compares the outcomes: if a lower-privileged identity gets the same successful
// response as the authorized one on a resource that should be restricted, that
// is broken access control. Positive signals are recorded as role-scoped
// hypotheses in the shared ledger (with the differential as evidence) so the
// coordinator/specialist can confirm and report them.
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

// authzIdentity is one identity the matrix replays a request as.
type authzIdentity struct {
	label   string            // human label, e.g. "second account (role B)"
	role    string            // ledger Role dimension: role-a | role-b | anonymous
	headers map[string]string // credential headers; nil for anonymous
}

// authzResult pairs an identity with its replay outcome.
type authzResult struct {
	identity authzIdentity
	resp     *httpclient.RawResponse
	err      error
}

// registerAuthzMatrixTool registers the Agent-bound authz_matrix tool. It is
// Agent-bound (not a standalone package) because it needs BOTH configured
// account credentials (a.targetAuth / a.targetAuthB), the scope config
// (a.localGuard), and the shared ledger — all of which live on the Agent.
func (a *Agent) registerAuthzMatrixTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "authz_matrix",
		Description: "Test access control by replaying ONE request as every configured identity — your primary session (role A; from configured target auth, or a logged-in HAR registered via ingest_har), a second account (role B) if the scan has one (configured, or a second logged-in HAR ingested via ingest_har role=b), and anonymous (no credentials) — then report the differential. This is the definitive check for IDOR/BOLA (a second user reading role A's object) and auth bypass/BFLA (anonymous reaching a protected resource). Point it at a resource that SHOULD be restricted to role A (e.g. role A's own object by id); if a lower identity gets the same successful response, that is broken access control. Positive signals are recorded as role-scoped hypotheses in the ledger with the differential as proof.",
		Parameters: []tools.Parameter{
			{Name: "url", Description: "URL of the object/action under test, ideally one owned by/authorized for role A (e.g. https://app/api/orders/1042).", Required: true},
			{Name: "method", Description: "HTTP method (default GET).", Required: false},
			{Name: "body", Description: "Request body for POST/PUT/PATCH.", Required: false},
			{Name: "headers", Description: `Optional JSON object of EXTRA headers common to all identities (e.g. {"Content-Type":"application/json"}). Do NOT put credentials here — identity credentials come from the scan's configured accounts.`, Required: false},
			{Name: "parameter", Description: "The object identifier/parameter under test (e.g. 'id'), used to label the hypothesis.", Required: false},
			{Name: "expect", Description: "Optional free-text note describing what an authorized response contains (recorded as the baseline).", Required: false},
		},
		Execute: a.authzMatrixTool,
	})
}

func (a *Agent) authzMatrixTool(args map[string]string) (tools.Result, error) {
	rawURL := strings.TrimSpace(args["url"])
	if rawURL == "" {
		return tools.Result{Error: "url is required"}, nil
	}
	method := strings.ToUpper(strings.TrimSpace(args["method"]))
	if method == "" {
		method = "GET"
	}
	body := args["body"]
	parameter := strings.TrimSpace(args["parameter"])
	expect := strings.TrimSpace(args["expect"])

	extra := map[string]string{}
	if h := strings.TrimSpace(args["headers"]); h != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(h), &m); err != nil {
			return tools.Result{Error: "invalid headers JSON: " + err.Error()}, nil
		}
		for k, v := range m {
			extra[k] = fmt.Sprint(v)
		}
	}

	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return tools.Result{Error: fmt.Sprintf("invalid url %q", args["url"])}, nil
	}
	// Defense-in-depth scope check (the agent loop also gates this tool): never
	// probe the operator's own machine/listener.
	if scopeguard.IsLocalOrListener(a.localGuard, u.Host) {
		return tools.Result{Error: fmt.Sprintf("%q points at the operator's machine or local network — refusing to run an authorization matrix against it.", u.Host)}, nil
	}

	identities := a.authzIdentities()
	if len(identities) < 2 {
		return tools.Result{Output: "authz_matrix needs at least two identities to compare, but this scan only has anonymous access configured. Provide a primary session — configure target auth, or run ingest_har on a logged-in HAR to register one — and ideally a second account, so the matrix can reveal a cross-identity access-control difference."}, nil
	}

	var delay time.Duration
	if a.scanCtx != nil {
		delay = a.scanCtx.RequestRatePolicy().Delay()
	}
	results := make([]authzResult, 0, len(identities))
	for i, id := range identities {
		if a.ctx != nil && a.ctx.Err() != nil {
			return tools.Result{Error: "scan canceled during authorization matrix"}, nil
		}
		if i > 0 && delay > 0 {
			time.Sleep(delay)
		}
		resp, sErr := httpclient.SendRaw(httpclient.RawRequest{
			Method:          method,
			URL:             u.String(),
			Headers:         mergeHeaders(extra, id.headers),
			Body:            body,
			FollowRedirects: false, // observe 3xx→login as a restriction signal
			TimeoutSec:      30,
		})
		results = append(results, authzResult{identity: id, resp: resp, err: sErr})
	}

	return a.analyzeAuthzMatrix(u, method, parameter, expect, results), nil
}

// authzIdentities returns the identities to test, highest privilege first.
// Anonymous is always included; role A/B only when their credentials are set.
//
// Role A is the operator-configured primary account (a.targetAuth) when set;
// otherwise it falls back to the scan's authenticated session — the credentials
// registered by ingest_har from a logged-in HAR. Without that fallback an
// authenticated HAR would seed IDOR/BOLA hypotheses but the matrix meant to
// test them would have only anonymous access and refuse to run. Role B follows
// the same rule: the operator's second account (a.targetAuthB) when set, else a
// second session ingested via ingest_har role=b — enabling true two-account
// IDOR/BOLA proof from two logged-in HARs.
func (a *Agent) authzIdentities() []authzIdentity {
	var ids []authzIdentity
	if hdrs := httpclient.ParseAuthHeaders(a.targetAuth); len(hdrs) > 0 {
		ids = append(ids, authzIdentity{label: "primary session (role A)", role: "role-a", headers: hdrs})
	} else if hdrs := a.sessionAuthHeaders(); len(hdrs) > 0 {
		ids = append(ids, authzIdentity{label: "primary session (role A, ingested)", role: "role-a", headers: hdrs})
	}
	if hdrs := httpclient.ParseAuthHeaders(a.targetAuthB); len(hdrs) > 0 {
		ids = append(ids, authzIdentity{label: "second account (role B)", role: "role-b", headers: hdrs})
	} else if hdrs := a.sessionAuthBHeaders(); len(hdrs) > 0 {
		ids = append(ids, authzIdentity{label: "second account (role B, ingested)", role: "role-b", headers: hdrs})
	}
	ids = append(ids, authzIdentity{label: "anonymous", role: "anonymous", headers: nil})
	return ids
}

// sessionAuthHeaders returns the authenticated-session headers registered for
// this scan context (e.g. by ingest_har), or nil when none. This lets the
// authorization matrix adopt an ingested session as role A when the operator
// did not configure a separate primary account.
func (a *Agent) sessionAuthHeaders() map[string]string {
	if a.scanCtx == nil {
		return nil
	}
	return httpclient.SessionAuthForContext(a.scanCtx.ID)
}

// sessionAuthBHeaders returns the second-account (role B) headers registered for
// this scan context (e.g. by ingest_har role=b), or nil when none. This lets
// the authorization matrix use an ingested second session as role B — enabling
// true two-account IDOR/BOLA testing — when the operator did not configure a
// separate second account.
func (a *Agent) sessionAuthBHeaders() map[string]string {
	if a.scanCtx == nil {
		return nil
	}
	return httpclient.SessionAuthBForContext(a.scanCtx.ID)
}

// analyzeAuthzMatrix compares each identity against the authorized baseline
// (role A, or the first authenticated identity), renders a report, and records
// broken-access-control signals as role-scoped ledger hypotheses.
func (a *Agent) analyzeAuthzMatrix(u *url.URL, method, parameter, expect string, results []authzResult) tools.Result {
	// Baseline = the first authenticated identity (role A preferred).
	var baseline *httpclient.RawResponse
	var baselineLabel string
	for _, r := range results {
		if r.identity.role != "anonymous" && r.resp != nil {
			baseline = r.resp
			baselineLabel = r.identity.label
			break
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Authorization matrix for %s %s (host %s):\n", method, u.EscapedPath(), u.Host)
	if expect != "" {
		fmt.Fprintf(&b, "Expected authorized response: %s\n", expect)
	}

	baselineDesc := "authorized baseline unavailable"
	if baseline != nil {
		baselineDesc = fmt.Sprintf("%s → status %d, %d bytes", baselineLabel, baseline.StatusCode, baseline.BodyLen)
	}

	l := a.ledger()
	recorded := 0
	for _, r := range results {
		if r.err != nil {
			fmt.Fprintf(&b, "  • %s: request error: %v\n", r.identity.label, r.err)
			continue
		}
		if r.resp == nil {
			fmt.Fprintf(&b, "  • %s: no response\n", r.identity.label)
			continue
		}
		// The baseline identity is annotated, not compared to itself.
		if r.identity.label == baselineLabel {
			fmt.Fprintf(&b, "  • %s: status %d, %d bytes  [authorized baseline]\n", r.identity.label, r.resp.StatusCode, r.resp.BodyLen)
			continue
		}
		verdict, broken, confidence := classifyAccess(baseline, r.resp)
		fmt.Fprintf(&b, "  • %s: status %d, %d bytes  → %s\n", r.identity.label, r.resp.StatusCode, r.resp.BodyLen, verdict)

		if broken && l != nil {
			class := "idor"
			if r.identity.role == "anonymous" {
				class = "auth-bypass"
			}
			h := l.Upsert(scanctx.Hypothesis{
				Title:      fmt.Sprintf("%s can access %s", r.identity.label, u.EscapedPath()),
				VulnClass:  class,
				Target:     u.Host,
				Endpoint:   u.EscapedPath(),
				Parameter:  parameter,
				Role:       r.identity.role,
				Baseline:   baselineDesc,
				Confidence: confidence,
				Status:     scanctx.HypothesisTesting,
				Origin:     "authz_matrix",
				NextAction: "Confirm the resource is meant to be restricted, then report as broken access control using this cross-identity differential as proof.",
			})
			l.AddEvidence(h.ID, scanctx.Evidence{
				Kind:       "exploit",
				Summary:    fmt.Sprintf("%s; %s got status %d / %d bytes for the same request — %s", baselineDesc, r.identity.label, r.resp.StatusCode, r.resp.BodyLen, verdict),
				Request:    fmt.Sprintf("%s %s  (identity: %s)", method, u.String(), r.identity.label),
				Response:   truncateForEvidence(r.resp.Body),
				Confidence: confidence,
				AgentID:    a.ledgerOrigin(),
				Source:     "authz_matrix",
			})
			// A cross-identity response comparison needs the model to confirm
			// the resource is meant to be restricted, so it stays testing.
			a.settleVerifierHypothesis(l, h.ID, false, "")
			recorded++
		}
	}

	if recorded > 0 {
		fmt.Fprintf(&b, "\nRecorded %d broken-access-control hypothesis(es) in the ledger. Confirm the resource is restricted, then report with report_vulnerability and link the finding via add_hypothesis_evidence(kind=finding_ref).\n", recorded)
	} else {
		b.WriteString("\nNo cross-identity access-control difference detected (lower identities were denied or returned their own content). This is evidence the endpoint enforces authorization for the tested object.\n")
	}
	return tools.Result{Output: b.String(), Metadata: map[string]any{"recorded_hypotheses": recorded}}
}

// classifyAccess compares a lower identity's response to the authorized
// baseline and returns a human verdict, whether it looks like broken access
// control, and a confidence in [0,1].
func classifyAccess(baseline, other *httpclient.RawResponse) (verdict string, broken bool, confidence float64) {
	switch {
	case other.StatusCode == 401 || other.StatusCode == 403:
		return "properly restricted (denied)", false, 0
	case other.StatusCode >= 300 && other.StatusCode < 400:
		return "redirected (likely to authentication) — restricted", false, 0
	case other.StatusCode >= 200 && other.StatusCode < 300:
		if baseline != nil && baseline.StatusCode >= 200 && baseline.StatusCode < 300 {
			if bodiesEquivalent(baseline.Body, other.Body) {
				return "SAME successful response as the authorized identity — likely broken access control", true, 0.85
			}
			return "accessible (2xx) but different content — may be this identity's own data; verify before reporting", false, 0.4
		}
		return "accessible (2xx) while the authorized baseline was not successful — verify", true, 0.5
	default:
		return fmt.Sprintf("status %d", other.StatusCode), false, 0
	}
}

// bodiesEquivalent reports whether two response bodies represent the same
// resource. Small bodies require an exact match; larger bodies tolerate a tiny
// length delta so dynamic tokens/timestamps don't mask a real match.
func bodiesEquivalent(a, b []byte) bool {
	ta := bytes.TrimSpace(a)
	tb := bytes.TrimSpace(b)
	if bytes.Equal(ta, tb) {
		return true
	}
	la, lb := len(ta), len(tb)
	if la < 64 || lb < 64 {
		return false
	}
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	maxLen := la
	if lb > maxLen {
		maxLen = lb
	}
	return float64(diff)/float64(maxLen) < 0.03
}

// mergeHeaders combines common extra headers with an identity's credential
// headers (credentials win on conflict). Returns nil when both are empty.
func mergeHeaders(extra, creds map[string]string) map[string]string {
	if len(extra) == 0 && len(creds) == 0 {
		return nil
	}
	out := make(map[string]string, len(extra)+len(creds))
	for k, v := range extra {
		out[k] = v
	}
	for k, v := range creds {
		out[k] = v
	}
	return out
}

// truncateForEvidence bounds a response body for ledger evidence. The ledger
// truncates again, but keeping this small avoids copying large bodies around.
func truncateForEvidence(body []byte) string {
	const max = 1024
	if len(body) <= max {
		return string(body)
	}
	return string(body[:max]) + "…(truncated)"
}
