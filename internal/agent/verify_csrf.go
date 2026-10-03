// Package agent — verify_csrf.go probes candidate CSRF endpoints using an
// ambient cookie and a forged Origin/Referer. HTTP acceptance is an observation,
// not proof of a state change or of browser cookie eligibility. Candidates need
// independent browser reproduction and a before/after victim-state comparison.
// The probe omits header credentials, declines non-simple browser requests,
// checks scope, rate policy and cancellation, and is disabled in passive mode.
package agent

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

func (a *Agent) registerVerifyCSRFTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "verify_csrf",
		Description: "Probe possible CSRF on a cookie-authenticated endpoint. Give it a url (or hypothesis_id) and a form body without an anti-CSRF token. It sends a forged Origin/Referer with the ambient Cookie only. Accepted HTTP responses remain candidates requiring independent browser reproduction and a before/after victim-state check. Raw Cookie replay cannot establish SameSite/Secure eligibility; a 2xx/3xx can be a no-op or login redirect. Non-simple methods/content types require separate browser/CORS verification and are not replayed. No exploit evidence is recorded from acceptance alone. Does not follow redirects; disabled in passive mode.",
		Parameters: []tools.Parameter{
			{Name: "url", Description: "Absolute URL (scheme://host/path) or path of the state-changing endpoint. One of url or hypothesis_id is required.", Required: false},
			{Name: "hypothesis_id", Description: "Optional ledger hypothesis id carrying an HTTP path; used when 'url' is not given.", Required: false},
			{Name: "method", Description: "HTTP method (default POST).", Required: false},
			{Name: "data", Description: "The state-change request body an attacker would forge, e.g. email=attacker@evil.example — WITHOUT any anti-CSRF token. URL-encoded form by default.", Required: false},
			{Name: "content_type", Description: "Content-Type for the body (default application/x-www-form-urlencoded).", Required: false},
		},
		Execute: a.verifyCSRFTool,
	})
}

func (a *Agent) verifyCSRFTool(args map[string]string) (tools.Result, error) {
	l := a.ledger()
	if l == nil {
		return tools.Result{Error: "ledger unavailable in this context"}, nil
	}
	if normalizeActivityMode(a.scanIntensity) == activityModePassive {
		return tools.Result{Error: "verify_csrf issues a live state-changing request and is disabled in passive scan mode."}, nil
	}

	rawEP := strings.TrimSpace(args["url"])
	baseHint := ""
	if rawEP == "" {
		id := strings.TrimSpace(args["hypothesis_id"])
		if id == "" {
			return tools.Result{Error: "one of url or hypothesis_id is required — pass the state-changing endpoint url, or a ledger hypothesis id carrying an HTTP path."}, nil
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
		return tools.Result{Error: "verify_csrf: " + err.Error()}, nil
	}
	u, perr := url.Parse(absURL)
	if perr != nil || u.Host == "" {
		return tools.Result{Error: fmt.Sprintf("verify_csrf: could not form a valid URL from %q", absURL)}, nil
	}

	// PRIMARY scope protection: the loop gate can't see this internally-resolved
	// host, so refuse the operator's own machine/listener here.
	if scopeguard.IsLocalOrListener(a.localGuard, u.Host) {
		return tools.Result{Error: fmt.Sprintf("verify_csrf refused: %q resolves to the operator's own machine or local network, not the engagement target.", u.Host)}, nil
	}

	method := strings.ToUpper(strings.TrimSpace(args["method"]))
	if method == "" {
		method = "POST"
	}
	data := args["data"]
	contentType := strings.TrimSpace(args["content_type"])
	if contentType == "" {
		contentType = "application/x-www-form-urlencoded"
	}

	headers := a.probeAuthHeaders()
	if headers == nil {
		headers = map[string]string{}
	}
	// Cookie authentication can coexist with a header credential. The forged
	// request sends only the ambient cookie, preserving that distinct test.
	if !hasAmbientCookie(headers) {
		return tools.Result{
			Output:   "CSRF NOT applicable: no ambient Cookie session is configured. An anonymous request accepted without victim authority may indicate missing abuse controls, but it is not proof of Cross-Site Request Forgery. Supply a legitimate cookie-authenticated session and retry the state-changing action.",
			Metadata: map[string]any{"csrf_confirmed": false, "reason": "no-cookie-auth"},
		}, nil
	}

	// Cross-site forms cannot synthesize authorization or custom credentials.
	ambient := map[string]string{}
	for key, value := range headers {
		if strings.EqualFold(key, "Cookie") {
			ambient["Cookie"] = value
		}
	}
	headers = ambient
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if (method != "POST" && method != "GET" && method != "HEAD") ||
		(mediaType != "application/x-www-form-urlencoded" && mediaType != "multipart/form-data" && mediaType != "text/plain") {
		return tools.Result{
			Output:   "CSRF inconclusive: this method or Content-Type requires browser preflight/CORS permission. Reproduce the actual cross-site browser request with the victim session and inspect the resulting state; raw HTTP replay would not establish browser feasibility.",
			Metadata: map[string]any{"csrf_confirmed": false, "inconclusive": true, "reason": "non-simple-browser-request"},
		}, nil
	}

	const attackerOrigin = "https://csrf-attacker.example"
	headers["Origin"] = attackerOrigin
	headers["Referer"] = attackerOrigin + "/"
	headers["Content-Type"] = contentType

	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	status, body, reqLine, sErr := a.sendStateChangeProbe(method, absURL, headers, data)
	if sErr != nil {
		return tools.Result{Error: fmt.Sprintf("verify_csrf: request failed: %v", sErr)}, nil
	}

	confirmed, note := csrfVerdict(status, body)
	endpoint := u.EscapedPath()

	if !confirmed {
		return tools.Result{
			Output:   fmt.Sprintf("CSRF NOT confirmed at %s: %s", endpoint, note),
			Metadata: map[string]any{"csrf_confirmed": false, "endpoint": endpoint, "status": status},
		}, nil
	}

	return tools.Result{
		Output:   fmt.Sprintf("CSRF candidate at %s: HTTP %d accepted the forged-origin %s request. %s\n%s\nAcceptance alone does not establish a state change or that a victim browser would send the cookie (SameSite/Secure protections may prevent it). Reproduce the actual cross-site browser action and compare victim state before/after; preserve the candidate for review until that proof exists.", endpoint, status, method, note, reqLine),
		Metadata: map[string]any{"csrf_confirmed": false, "csrf_candidate": true, "inconclusive": true, "endpoint": endpoint, "status": status},
	}, nil
}

func hasAmbientCookie(headers map[string]string) bool {
	for name, value := range headers {
		if strings.EqualFold(strings.TrimSpace(name), "Cookie") && strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

// sendStateChangeProbe issues one state-changing request (the host was
// scope-checked by the caller) and returns the status code, response body, and a
// compact request line.
func (a *Agent) sendStateChangeProbe(method, rawURL string, headers map[string]string, body string) (status int, respBody, reqLine string, err error) {
	reqLine = fmt.Sprintf("%s %s (forged cross-site Origin, no CSRF token)", method, rawURL)
	resp, e := httpclient.SendRaw(httpclient.RawRequest{
		Method:          method,
		URL:             rawURL,
		Headers:         headers,
		Body:            body,
		FollowRedirects: false,
		TimeoutSec:      30,
	})
	if e != nil {
		return 0, "", reqLine, e
	}
	return resp.StatusCode, string(resp.Body), reqLine, nil
}

// csrfVerdict classifies HTTP acceptance only. The caller must not interpret an
// accepted response as proof of a victim state change or browser exploitability.
func csrfVerdict(status int, body string) (confirmed bool, note string) {
	lb := strings.ToLower(body)
	if status == 401 || status == 403 || status == 419 || csrfRejectionMarker(lb) {
		return false, fmt.Sprintf("the response signals a possible anti-CSRF or authorization rejection (HTTP %d). Inspect actual victim state and browser behavior before concluding exploitability.", status)
	}
	if status >= 200 && status < 400 {
		return true, "the forged cross-site request was accepted with no anti-CSRF token."
	}
	return false, fmt.Sprintf("the request returned HTTP %d (not a success) — could not confirm the state change was accepted; retry with a valid body and method.", status)
}

// csrfRejectionMarker reports whether a response body signals an anti-CSRF /
// authorization rejection.
func csrfRejectionMarker(lb string) bool {
	for _, m := range []string{
		"invalid token", "missing token", "token mismatch",
		"token required", "invalid csrf", "csrf verification failed", "csrf token missing", "csrf token required", "csrf token mismatch", "xsrf token missing", "xsrf token mismatch", "forbidden", "not allowed",
		"access denied", "unauthorized", "authentication required",
	} {
		if strings.Contains(lb, m) {
			return true
		}
	}
	return false
}
