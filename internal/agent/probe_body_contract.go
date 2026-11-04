package agent

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

// bodyContractCandidates is a compact, generic set of high-signal JSON field
// names the prober tries when discovering which fields a body endpoint accepts.
// Kept deliberately small so the probe stays bounded; the caller can extend it
// with the `fields` argument when it has endpoint-specific guesses.
var bodyContractCandidates = []string{
	"id", "user_id", "userId", "email", "username", "password", "name", "title",
	"role", "token", "amount", "price", "quantity", "status", "type", "action",
	"query", "q", "search", "page", "limit", "data", "value", "enabled",
}

const bodyContractSentinel = "xalgorix_probe"

// registerProbeBodyContractTool installs probe_body_contract: a deterministic
// JSON body-contract discovery tool. arjun and the surface machinery only see
// query/form parameters, so a JSON API that answers a bare request with its own
// validation error ("code 34: field missing", "email is required") is a dead
// end today. This probe turns that error channel into data: it sends a baseline
// body, then field mutations (remove a seed field, add a candidate field, swap a
// field's type), and diffs the app's own status/error signatures to infer which
// fields are required, which are accepted, and which are rejected as unknown —
// so the agent can then build a valid body and inject into the real parameters.
func (a *Agent) registerProbeBodyContractTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "probe_body_contract",
		Description: "Discover the JSON body contract of a POST/PUT/PATCH endpoint by reading the app's own validation errors. Give a url (or hypothesis_id) and optionally a seed_body (a known-good or partial JSON object) and extra candidate `fields`. It sends a baseline body, then removes each seed field, adds candidate fields, and swaps field types, diffing the returned status and error code/message to classify fields as REQUIRED, RECOGNIZED/accepted, or REJECTED-as-unknown. Use it when a JSON endpoint answers with a validation error and you cannot tell which fields it wants — then build a valid body and inject into the discovered parameters (verify_sqli/verify_ssti). Bounded request count, uses scan auth, never follows redirects, disabled in passive mode. This is discovery, not exploitation: it records no finding.",
		Parameters: []tools.Parameter{
			{Name: "url", Description: "Absolute URL or path of the JSON endpoint. Supply this or hypothesis_id.", Required: false},
			{Name: "hypothesis_id", Description: "Ledger hypothesis carrying the endpoint; used when url is absent.", Required: false},
			{Name: "method", Description: "Body method: POST (default), PUT, or PATCH.", Required: false},
			{Name: "seed_body", Description: "Optional known-good or partial JSON object (e.g. {\"email\":\"a@b.c\"}). Its fields are probed for required/typed; omit to discover from an empty body.", Required: false},
			{Name: "fields", Description: "Optional comma-separated extra candidate field names to test for acceptance, beyond the built-in list.", Required: false},
		},
		Execute: a.probeBodyContractTool,
	})
}

func (a *Agent) probeBodyContractTool(args map[string]string) (tools.Result, error) {
	l := a.ledger()
	if l == nil {
		return tools.Result{Error: "ledger unavailable in this context"}, nil
	}
	if normalizeActivityMode(a.scanIntensity) == activityModePassive {
		return tools.Result{Error: "probe_body_contract issues live requests and is disabled in passive scan mode."}, nil
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
		return tools.Result{Error: "probe_body_contract: " + err.Error()}, nil
	}
	u, perr := url.Parse(absURL)
	if perr != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return tools.Result{Error: "probe_body_contract: a valid HTTP(S) endpoint is required"}, nil
	}
	if scopeguard.IsLocalOrListener(a.localGuard, u.Host) {
		return tools.Result{Error: fmt.Sprintf("probe_body_contract refused: %q resolves to the operator's own machine or local network, not the engagement target.", u.Host)}, nil
	}

	method := strings.ToUpper(strings.TrimSpace(args["method"]))
	if method == "" {
		method = "POST"
	}
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return tools.Result{Error: "probe_body_contract: method must be POST, PUT, or PATCH (body-contract discovery needs a request body)"}, nil
	}

	base := map[string]any{}
	if seed := strings.TrimSpace(args["seed_body"]); seed != "" {
		if err := json.Unmarshal([]byte(seed), &base); err != nil {
			return tools.Result{Error: "probe_body_contract: seed_body must be a JSON object, e.g. {\"email\":\"a@b.c\"}: " + err.Error()}, nil
		}
	}
	seedFields := sortedKeys(base)

	headers := a.probeAuthHeaders()
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = "application/json"

	send := func(bodyMap map[string]any) (*bodyProbeResult, string) {
		if stop := a.injectionRateGate(); stop != "" {
			return nil, stop
		}
		payload, _ := json.Marshal(bodyMap)
		resp, e := httpclient.SendRaw(httpclient.RawRequest{
			Method: method, URL: u.String(), Headers: headers,
			Body: string(payload), FollowRedirects: false, TimeoutSec: 30,
		})
		if e != nil {
			return nil, fmt.Sprintf("request failed: %v", e)
		}
		return &bodyProbeResult{status: resp.StatusCode, sig: bodyErrorSignature(string(resp.Body)), body: string(resp.Body)}, ""
	}

	baseline, stop := send(base)
	if stop != "" {
		return tools.Result{Error: "probe_body_contract: " + stop}, nil
	}

	var required, removable, recognized, rejected, ignored, typed []string

	// Capture the first validation error the app emits across any probe, so the
	// output hands the agent the app's own error channel ("code 34 / email is
	// required") even when the baseline body was accepted.
	errSample := ""
	noteError := func(r *bodyProbeResult) {
		if errSample == "" && r != nil && r.status >= 400 {
			if ex := boundedText(r.body, 300); ex != "" {
				errSample = ex
			}
		}
	}
	noteError(baseline)

	// Required-field discovery: remove each seed field and see whether the app
	// now complains about it (status worsens, or it names the field / "required").
	for _, f := range seedFields {
		reduced := cloneWithout(base, f)
		r, stop := send(reduced)
		if stop != "" {
			break
		}
		noteError(r)
		switch {
		case r.status == baseline.status && r.sig == baseline.sig:
			removable = append(removable, f)
		case isWorse(baseline.status, r.status) || mentionsFieldRequirement(r.body, f):
			required = append(required, f)
		default:
			removable = append(removable, f)
		}
	}

	// Accepted-field discovery: add each candidate and classify by how the app's
	// validation signature moves.
	for _, f := range candidateFields(args["fields"], base) {
		added := cloneWith(base, f, bodyContractSentinel)
		r, stop := send(added)
		if stop != "" {
			break
		}
		noteError(r)
		switch {
		case mentionsUnknownField(r.body, f) || (isWorse(baseline.status, r.status) && bodyMentions(r.body, f)):
			rejected = append(rejected, f)
		case r.status != baseline.status || r.sig != baseline.sig:
			recognized = append(recognized, f)
		default:
			ignored = append(ignored, f)
		}
	}

	// Type probing: swap each seed field's JSON type and see if validation reacts.
	for _, f := range seedFields {
		swapped := cloneWith(base, f, typeSwap(base[f]))
		r, stop := send(swapped)
		if stop != "" {
			break
		}
		if r.status != baseline.status || r.sig != baseline.sig {
			typed = append(typed, f)
		}
	}

	return tools.Result{
		Output: renderBodyContract(method, u.EscapedPath(), baseline, errSample, required, removable, recognized, rejected, ignored, typed),
		Metadata: map[string]any{
			"endpoint":        u.EscapedPath(),
			"method":          method,
			"baseline_status": baseline.status,
			"required":        required,
			"recognized":      recognized,
			"rejected":        rejected,
			"type_validated":  typed,
		},
	}, nil
}

type bodyProbeResult struct {
	status int
	sig    string
	body   string
}

// bodyErrorSignature reduces a response body to a stable comparison key: the
// values of common top-level error keys when the body is JSON, else a normalized
// prefix of the body. This lets the prober tell "the validation complaint
// changed" from "same response" without being fooled by dynamic noise.
func bodyErrorSignature(body string) string {
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") {
		var m map[string]any
		if err := json.Unmarshal([]byte(trimmed), &m); err == nil {
			var parts []string
			for _, k := range []string{"code", "error", "errors", "message", "detail", "title", "status", "type"} {
				if v, ok := m[k]; ok {
					parts = append(parts, fmt.Sprintf("%s=%v", k, v))
				}
			}
			if len(parts) > 0 {
				return normalizeBodyForDiff(strings.Join(parts, "|"))
			}
		}
	}
	n := normalizeBodyForDiff(trimmed)
	if len(n) > 160 {
		n = n[:160]
	}
	return n
}

// isWorse reports whether `now` is an error status that `base` was not, i.e. the
// mutation pushed an accepted/other response into the 4xx validation band.
func isWorse(base, now int) bool {
	return now >= 400 && now < 500 && (base < 400 || base >= 500)
}

func bodyMentions(body, token string) bool {
	return token != "" && strings.Contains(strings.ToLower(body), strings.ToLower(token))
}

func mentionsFieldRequirement(body, field string) bool {
	l := strings.ToLower(body)
	if !bodyMentions(body, field) {
		return strings.Contains(l, "required") || strings.Contains(l, "missing") || strings.Contains(l, "mandatory")
	}
	return strings.Contains(l, "required") || strings.Contains(l, "missing") ||
		strings.Contains(l, "mandatory") || strings.Contains(l, "must")
}

func mentionsUnknownField(body, field string) bool {
	l := strings.ToLower(body)
	if !bodyMentions(body, field) {
		return false
	}
	return strings.Contains(l, "unknown") || strings.Contains(l, "unexpected") ||
		strings.Contains(l, "not allowed") || strings.Contains(l, "not permitted") ||
		strings.Contains(l, "not recognized") || strings.Contains(l, "invalid field") ||
		strings.Contains(l, "additional propert")
}

// candidateFields returns the built-in candidates plus any caller-supplied
// names, excluding fields already present in the base body, deduped and bounded.
func candidateFields(extra string, base map[string]any) []string {
	seen := map[string]bool{}
	for k := range base {
		seen[k] = true
	}
	var out []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || !validParamName(name) {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, e := range strings.Split(extra, ",") {
		add(e)
	}
	for _, c := range bodyContractCandidates {
		if len(out) >= 24 {
			break
		}
		add(c)
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func cloneWithout(m map[string]any, drop string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k != drop {
			out[k] = v
		}
	}
	return out
}

func cloneWith(m map[string]any, key string, val any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	out[key] = val
	return out
}

// typeSwap returns a value of a different JSON type than v, so a type-validating
// endpoint reacts: strings become a number, everything else becomes a string.
func typeSwap(v any) any {
	switch v.(type) {
	case string:
		return 12345
	default:
		return bodyContractSentinel
	}
}

func renderBodyContract(method, endpoint string, baseline *bodyProbeResult, errSample string, required, removable, recognized, rejected, ignored, typed []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "JSON body-contract probe of %s %s.\n", method, endpoint)
	fmt.Fprintf(&b, "Baseline (minimal body) → HTTP %d; the app's own response signature: %s\n", baseline.status, shortSig(baseline.sig))
	writeList := func(label string, xs []string) {
		if len(xs) > 0 {
			fmt.Fprintf(&b, "%s: %s\n", label, strings.Join(xs, ", "))
		}
	}
	writeList("REQUIRED (removing them provokes a missing/required error)", required)
	writeList("RECOGNIZED (accepting them changed the app's validation signature)", recognized)
	writeList("REJECTED as unknown (strict schema — the app names them as not allowed)", rejected)
	writeList("TYPE-VALIDATED (swapping the value type changed the response)", typed)
	writeList("removable (dropping them did not change the response)", removable)
	writeList("ignored (adding them had no effect)", ignored)
	if len(required) == 0 && len(recognized) == 0 && len(rejected) == 0 {
		b.WriteString("No field moved the app's response — the endpoint may not validate a JSON body here, need a different content type, or require auth you do not hold. ")
	}
	b.WriteString("\nThis is discovery only (no finding recorded). Next: assemble a body with the REQUIRED fields, then inject into the REQUIRED/RECOGNIZED fields (verify_sqli / verify_ssti with the JSON body) to test them.")
	if errSample != "" {
		fmt.Fprintf(&b, "\n\nA validation error the app returned (its error channel):\n%s", errSample)
	} else if excerpt := boundedText(baseline.body, 300); excerpt != "" {
		fmt.Fprintf(&b, "\n\nBaseline response excerpt:\n%s", excerpt)
	}
	return b.String()
}

func shortSig(s string) string {
	if s == "" {
		return "(empty)"
	}
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}
