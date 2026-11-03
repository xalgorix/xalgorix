package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

const timingNoncePlaceholder = "{{TIMING_NONCE}}"

// registerVerifyTimingTool installs a bounded, generic timing-differential
// confirmer for blind server-side injection. It deliberately accepts the exact
// baseline and probe bodies rather than manufacturing product-specific exploit
// strings: reconnaissance/advisory research identifies a safe delay primitive,
// while this tool supplies the statistically meaningful replay and control.
func (a *Agent) registerVerifyTimingTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "verify_timing",
		Description: "Deterministically CONFIRM a blind server-side injection/RCE primitive by repeated differential timing. Supply the exact safe baseline_body and delay-inducing probe_body, expected_delay_ms, and the live URL (or hypothesis_id). It performs one baseline warm-up, then 3-5 interleaved baseline/probe pairs with alternating order; confirmation requires a large median separation and agreement in all but at most one pair. Use {{TIMING_NONCE}} in bodies when the target requires a unique trigger/table/name per request. This is the preferred fallback when an exact product/CVE lead has a harmless server-native delay primitive (for example Java Thread.sleep) but OAST is unavailable or ambiguous. It records timing-only exploit proof in the ledger, never body contents. A banner, one slow response, timeout, or unpaired timing hunch is never confirmation. Uses scan auth, honors rate limits, does not follow redirects, and is disabled in passive mode.",
		Parameters: []tools.Parameter{
			{Name: "url", Description: "Absolute URL or target path to test. Supply this or hypothesis_id.", Required: false},
			{Name: "hypothesis_id", Description: "Ledger hypothesis carrying the endpoint; used when url is absent.", Required: false},
			{Name: "method", Description: "HTTP method (default POST).", Required: false},
			{Name: "headers", Description: "Optional JSON object of request headers, e.g. {\"Content-Type\":\"application/json\"}. Scan auth is merged separately.", Required: false},
			{Name: "baseline_body", Description: "Exact benign/control request body. May contain {{TIMING_NONCE}}.", Required: true},
			{Name: "probe_body", Description: "Exact request body containing a SAFE server-side delay primitive. May contain {{TIMING_NONCE}}.", Required: true},
			{Name: "expected_delay_ms", Description: "Intended delay in milliseconds (1000-15000).", Required: true},
			{Name: "trials", Description: "Number of paired measurements (default 3; allowed 3-5).", Required: false},
			{Name: "vuln_class", Description: "Class being confirmed, such as rce, cmdi, code-injection, jndi-injection, or sqli.", Required: true},
			{Name: "parameter", Description: "Optional vulnerable JSON/form/query field name for ledger/reporting context.", Required: false},
		},
		Execute: a.verifyTimingTool,
	})
}

func (a *Agent) verifyTimingTool(args map[string]string) (tools.Result, error) {
	l := a.ledger()
	if l == nil {
		return tools.Result{Error: "ledger unavailable in this context"}, nil
	}
	if normalizeActivityMode(a.scanIntensity) == activityModePassive {
		return tools.Result{Error: "verify_timing issues live injection requests and is disabled in passive scan mode."}, nil
	}

	rawEP := strings.TrimSpace(args["url"])
	baseHint := ""
	linkedHypothesis := strings.TrimSpace(args["hypothesis_id"])
	if rawEP == "" {
		if linkedHypothesis == "" {
			return tools.Result{Error: "url or hypothesis_id is required"}, nil
		}
		h, ok := l.Get(linkedHypothesis)
		if !ok {
			return tools.Result{Error: fmt.Sprintf("unknown hypothesis id %q", linkedHypothesis)}, nil
		}
		rawEP, baseHint = strings.TrimSpace(h.Endpoint), strings.TrimSpace(h.Target)
	}
	absURL, err := a.resolveInjectionURL(rawEP, baseHint)
	if err != nil {
		return tools.Result{Error: "verify_timing: " + err.Error()}, nil
	}
	u, err := url.Parse(absURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return tools.Result{Error: "verify_timing: a valid HTTP(S) URL is required"}, nil
	}
	if scopeguard.IsLocalOrListener(a.localGuard, u.Host) {
		return tools.Result{Error: fmt.Sprintf("verify_timing refused: %q resolves to the operator's own machine or local network, not the engagement target.", u.Host)}, nil
	}

	method := strings.ToUpper(strings.TrimSpace(args["method"]))
	if method == "" {
		method = "POST"
	}
	baselineTemplate := args["baseline_body"]
	probeTemplate := args["probe_body"]
	if strings.TrimSpace(baselineTemplate) == "" || strings.TrimSpace(probeTemplate) == "" {
		return tools.Result{Error: "baseline_body and probe_body are required and must be non-empty"}, nil
	}
	if baselineTemplate == probeTemplate {
		return tools.Result{Error: "baseline_body and probe_body must differ"}, nil
	}
	if len(baselineTemplate) > 256<<10 || len(probeTemplate) > 256<<10 {
		return tools.Result{Error: "baseline_body and probe_body are limited to 256 KiB each"}, nil
	}

	expectedMS, err := strconv.Atoi(strings.TrimSpace(args["expected_delay_ms"]))
	if err != nil || expectedMS < 1000 || expectedMS > 15000 {
		return tools.Result{Error: "expected_delay_ms must be an integer from 1000 through 15000"}, nil
	}
	trials := 3
	if raw := strings.TrimSpace(args["trials"]); raw != "" {
		trials, err = strconv.Atoi(raw)
		if err != nil || trials < 3 || trials > 5 {
			return tools.Result{Error: "trials must be an integer from 3 through 5"}, nil
		}
	}
	vulnClass := normalizeTimingClass(args["vuln_class"])
	if vulnClass == "" {
		return tools.Result{Error: "vuln_class must name a blind server-side injection class (for example rce, cmdi, code-injection, jndi-injection, or sqli)"}, nil
	}

	extraHeaders := map[string]string{}
	if raw := strings.TrimSpace(args["headers"]); raw != "" {
		if err := json.Unmarshal([]byte(raw), &extraHeaders); err != nil {
			return tools.Result{Error: "headers must be a JSON object whose values are strings"}, nil
		}
	}
	headers := mergeHeaders(extraHeaders, a.probeAuthHeaders())
	if headers == nil {
		headers = map[string]string{}
	}
	if _, ok := headerValue(headers, "Content-Type"); !ok &&
		(strings.HasPrefix(strings.TrimSpace(baselineTemplate), "{") || strings.HasPrefix(strings.TrimSpace(probeTemplate), "{")) {
		headers["Content-Type"] = "application/json"
	}

	timeoutSec := expectedMS/1000 + 15
	if timeoutSec > 60 {
		timeoutSec = 60
	}
	send := func(template string) (*httpclient.RawResponse, string, error) {
		if stop := a.injectionRateGate(); stop != "" {
			return nil, "", fmt.Errorf("%s", stop)
		}
		body := strings.ReplaceAll(template, timingNoncePlaceholder, newTimingNonce())
		resp, sendErr := httpclient.SendRaw(httpclient.RawRequest{
			Method: method, URL: absURL, Headers: headers, Body: body,
			FollowRedirects: false, TimeoutSec: timeoutSec,
		})
		return resp, shortSHA256(body), sendErr
	}

	// Discard one benign warm-up so connection establishment, class loading, or
	// lazy route initialization cannot masquerade as the exploit differential.
	if _, _, err := send(baselineTemplate); err != nil {
		return tools.Result{Error: fmt.Sprintf("verify_timing: baseline warm-up failed: %v", err)}, nil
	}

	baseline := make([]time.Duration, 0, trials)
	probe := make([]time.Duration, 0, trials)
	pairDiffs := make([]time.Duration, 0, trials)
	baselineStatuses := make([]int, 0, trials)
	probeStatuses := make([]int, 0, trials)
	baselineHashes := make([]string, 0, trials)
	probeHashes := make([]string, 0, trials)
	for i := 0; i < trials; i++ {
		var bResp, pResp *httpclient.RawResponse
		var bHash, pHash string
		if i%2 == 0 {
			bResp, bHash, err = send(baselineTemplate)
			if err == nil {
				pResp, pHash, err = send(probeTemplate)
			}
		} else {
			pResp, pHash, err = send(probeTemplate)
			if err == nil {
				bResp, bHash, err = send(baselineTemplate)
			}
		}
		if err != nil {
			return tools.Result{Error: fmt.Sprintf("verify_timing: paired request %d failed: %v; network errors/timeouts are not timing proof", i+1, err)}, nil
		}
		baseline = append(baseline, bResp.Elapsed)
		probe = append(probe, pResp.Elapsed)
		pairDiffs = append(pairDiffs, pResp.Elapsed-bResp.Elapsed)
		baselineStatuses = append(baselineStatuses, bResp.StatusCode)
		probeStatuses = append(probeStatuses, pResp.StatusCode)
		baselineHashes = append(baselineHashes, bHash)
		probeHashes = append(probeHashes, pHash)
	}

	confirmed, stats := timingDifferentialVerdict(baseline, probe, time.Duration(expectedMS)*time.Millisecond)
	proof := fmt.Sprintf("Repeated timing differential at %s %s: baseline_ms=%v; probe_ms=%v; pair_delta_ms=%v; median_baseline_ms=%d; median_probe_ms=%d; median_delta_ms=%d; expected_delay_ms=%d; supporting_pairs=%d/%d; baseline_status=%v; probe_status=%v; baseline_body_sha256=%v; probe_body_sha256=%v.",
		method, absURL, durationsMS(baseline), durationsMS(probe), durationsMS(pairDiffs), stats.BaselineMedian.Milliseconds(), stats.ProbeMedian.Milliseconds(), stats.MedianDelta.Milliseconds(), expectedMS, stats.SupportingPairs, trials, baselineStatuses, probeStatuses, baselineHashes, probeHashes)
	if !confirmed {
		return tools.Result{
			Output: fmt.Sprintf("Timing injection NOT confirmed: %s %s Do not report this as exploitation. %s", stats.Reason, proof, timingRetryGuidance(stats)),
			Metadata: map[string]any{
				"timing_confirmed": false, "endpoint": u.EscapedPath(), "vuln_class": vulnClass,
				"baseline_ms": durationsMS(baseline), "probe_ms": durationsMS(probe),
			},
		}, nil
	}

	parameter := strings.TrimSpace(args["parameter"])
	confirm := fmt.Sprintf("Blind %s CONFIRMED by a repeated server-side timing differential at %s: %d/%d paired probes supported the delay; median baseline %d ms versus median probe %d ms (delta %d ms for an intended %d ms delay).",
		strings.ToUpper(vulnClass), u.EscapedPath(), stats.SupportingPairs, trials, stats.BaselineMedian.Milliseconds(), stats.ProbeMedian.Milliseconds(), stats.MedianDelta.Milliseconds(), expectedMS)
	h := l.Upsert(scanctx.Hypothesis{
		Title:      "Blind " + strings.ToUpper(vulnClass) + " timing execution at " + u.EscapedPath(),
		VulnClass:  vulnClass,
		Endpoint:   u.EscapedPath(),
		Parameter:  parameter,
		Target:     baseURLOf(u),
		Confidence: 0.95,
		Status:     scanctx.HypothesisTesting,
		Origin:     "verify_timing",
		NextAction: "Report the confirmed injection with verification_method=time_based and the complete repeated baseline/probe timing differential; then link the finding via add_hypothesis_evidence(kind=finding_ref).",
	})
	l.AddEvidence(h.ID, scanctx.Evidence{
		Kind:       "exploit",
		Summary:    confirm + " " + proof,
		Request:    fmt.Sprintf("%s %s (baseline/probe bodies stored only as SHA-256 prefixes)", method, absURL),
		Response:   proof,
		Confidence: 0.95,
		AgentID:    a.ledgerOrigin(),
		Source:     "verify_timing",
	})
	a.settleVerifierHypothesis(l, h.ID, true, "report the repeated timing differential with verification_method=time_based")

	return tools.Result{
		Output: confirm + fmt.Sprintf(" Recorded exploit-proven evidence in ledger %s. Call report_vulnerability now with verification_method=time_based, hypothesis_id=%s, the exact endpoint/method/class, and this exploitation_proof:\n\n%s", h.ID, h.ID, proof),
		Metadata: map[string]any{
			"timing_confirmed": true, "endpoint": u.EscapedPath(), "vuln_class": vulnClass,
			"hypothesis_id": h.ID, "baseline_ms": durationsMS(baseline), "probe_ms": durationsMS(probe),
		},
	}, nil
}

type timingStats struct {
	BaselineMedian  time.Duration
	ProbeMedian     time.Duration
	MedianDelta     time.Duration
	SupportingPairs int
	Reason          string
}

func timingDifferentialVerdict(baseline, probe []time.Duration, expected time.Duration) (bool, timingStats) {
	stats := timingStats{}
	if len(baseline) < 3 || len(baseline) != len(probe) || expected < time.Second {
		stats.Reason = "at least three paired samples and an expected delay of at least one second are required."
		return false, stats
	}
	stats.BaselineMedian = medianDuration(baseline)
	stats.ProbeMedian = medianDuration(probe)
	stats.MedianDelta = stats.ProbeMedian - stats.BaselineMedian
	medianThreshold := maxDuration(750*time.Millisecond, expected*6/10)
	pairThreshold := maxDuration(500*time.Millisecond, expected*4/10)
	for i := range baseline {
		if probe[i]-baseline[i] >= pairThreshold {
			stats.SupportingPairs++
		}
	}
	if stats.MedianDelta < medianThreshold {
		stats.Reason = fmt.Sprintf("median separation %d ms is below the required %d ms.", stats.MedianDelta.Milliseconds(), medianThreshold.Milliseconds())
		return false, stats
	}
	if stats.SupportingPairs < len(baseline)-1 {
		stats.Reason = fmt.Sprintf("only %d/%d pairs reproduced the delay; at least %d are required.", stats.SupportingPairs, len(baseline), len(baseline)-1)
		return false, stats
	}
	stats.Reason = "the repeated differential satisfies the median and paired-support thresholds."
	return true, stats
}

func normalizeTimingClass(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "rce", "blind-rce", "remote-code-execution", "cmdi", "command-injection", "command_injection",
		"code-injection", "code_injection", "expression-injection", "jdbc-injection", "jndi-injection", "deserialization":
		return "rce"
	case "sqli", "sql-injection", "sql_injection", "blind-sqli":
		return "sqli"
	case "nosqli", "nosql-injection", "nosql_injection":
		return "nosqli"
	case "ssti", "server-side-template-injection", "server_side_template_injection":
		return "ssti"
	}
	return ""
}

func headerValue(headers map[string]string, name string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

func newTimingNonce() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err == nil {
		return "xalg_" + hex.EncodeToString(raw)
	}
	return "xalg_" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func shortSHA256(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:8])
}

func durationsMS(values []time.Duration) []int64 {
	out := make([]int64, len(values))
	for i, value := range values {
		out[i] = value.Milliseconds()
	}
	return out
}

func medianDuration(values []time.Duration) time.Duration {
	copyValues := append([]time.Duration(nil), values...)
	sort.Slice(copyValues, func(i, j int) bool { return copyValues[i] < copyValues[j] })
	mid := len(copyValues) / 2
	if len(copyValues)%2 == 1 {
		return copyValues[mid]
	}
	return (copyValues[mid-1] + copyValues[mid]) / 2
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func timingRetryGuidance(stats timingStats) string {
	if stats.SupportingPairs == 0 {
		return "The supplied delay primitive likely did not execute; verify the request shape and use a server-native primitive rather than assuming curl/wget exists."
	}
	return "The signal was unstable; check target load and request equivalence, then retry once with a larger safe delay."
}
