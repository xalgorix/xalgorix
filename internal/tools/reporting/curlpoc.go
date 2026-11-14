package reporting

// curlpoc.go guarantees that every finding reported against an HTTP(S) target
// carries a copy-pasteable curl command for the affected request in its PoC
// script, so a report reader can reproduce the request the scanner made with a
// single line. A reviewer told us a replayable curl is the difference between
// trusting a finding and skimming past it, and today not every finding has one.
//
// The command is built from the finding's own structured fields — the reported
// HTTP method and the affected endpoint/target URL — NOT by parsing exploit
// text out of the proof. The exact payload stays in the exploitation proof;
// this only guarantees a replayable request skeleton pointing at it.
//
// It never replaces or edits a curl the agent already wrote, and it leaves
// non-HTTP findings (source-code review with a code:// subject, raw TCP
// services such as redis://) untouched. Consistent with the rest of this
// package, a missing field is salvaged rather than treated as a reason to drop
// a real finding.

import (
	"net/url"
	"regexp"
	"strings"
)

// curlPresentRE matches a curl invocation at the start of the PoC or after a
// shell separator / quote, so an existing command is never duplicated.
var curlPresentRE = regexp.MustCompile(`(?:^|[\s;&|("` + "`" + `])curl\s`)

// curlLeadingVerbRE strips a leading HTTP verb from an endpoint written as
// "POST https://host/graphql".
var curlLeadingVerbRE = regexp.MustCompile(`^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+`)

// ensureCurlPoC fills args["poc_script_code"] with a replayable curl command
// for an HTTP(S) finding's affected endpoint when it does not already contain
// one. It is a no-op for non-HTTP findings.
func ensureCurlPoC(args map[string]string, target, endpoint string) {
	if curlPresentRE.MatchString(args["poc_script_code"]) {
		return
	}
	reqURL, ok := affectedRequestURL(endpoint, target)
	if !ok {
		return
	}

	method := strings.ToUpper(curlFirstToken(args["method"]))
	curl := "curl -sk"
	if method != "" && method != "GET" {
		curl += " -X " + method
	}
	curl += " " + curlShellQuote(reqURL)
	if method != "" && method != "GET" && method != "HEAD" {
		curl += " --data '<body — see exploitation proof>'"
	}

	block := "# Replayable request for the affected endpoint; the exact payload is in the exploitation proof.\n" + curl
	if existing := strings.TrimSpace(args["poc_script_code"]); existing != "" {
		block += "\n\n" + existing
	}
	args["poc_script_code"] = block
}

// affectedRequestURL resolves the finding's affected request URL from the
// reported endpoint (preferred) or target. It returns ok=false for a finding
// that is not addressable over HTTP(S), so those keep no curl PoC.
func affectedRequestURL(endpoint, target string) (string, bool) {
	ep := strings.TrimRight(curlFirstToken(curlLeadingVerbRE.ReplaceAllString(strings.TrimSpace(endpoint), "")), ",;)")

	// 1. Endpoint is already an absolute http(s) URL — keep its exact bytes
	// (literal ../ segments and encoding matter for replay).
	if parseHTTPURL(ep) != nil {
		return ep, true
	}

	// 2. Target is an absolute http(s) URL; join an endpoint path when present.
	if base := parseHTTPURL(curlFirstToken(target)); base != nil {
		origin := base.Scheme + "://" + base.Host
		if strings.HasPrefix(ep, "/") {
			return origin + ep, true
		}
		if base.Path != "" && base.Path != "/" {
			return origin + base.Path, true
		}
		return origin, true
	}

	// 3. Target is a bare host[:port] with no scheme — synthesize one.
	if t := curlFirstToken(target); t != "" && !strings.Contains(t, "://") {
		if u, err := url.Parse("//" + t); err == nil && u.Hostname() != "" {
			scheme := "https"
			if p := u.Port(); p != "" && p != "443" {
				scheme = "http"
			}
			origin := scheme + "://" + u.Host
			if strings.HasPrefix(ep, "/") {
				return origin + ep, true
			}
			return origin, true
		}
	}

	return "", false
}

// parseHTTPURL parses raw as an absolute http(s) URL, or returns nil. A bare
// host or a non-HTTP scheme (code://, redis://, ftp://) yields nil.
func parseHTTPURL(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.Contains(raw, "://") {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil
	}
	return u
}

func curlFirstToken(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func curlShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
