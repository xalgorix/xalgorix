package web

import (
	"path"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// effectiveWildcardExcludes merges the server-wide subdomain exclusion patterns
// (XALGORIX_WILDCARD_EXCLUDE, via config) with any per-scan patterns supplied on
// the scan request (exclude_subdomains). The result is trimmed, lowercased and
// empty-free, config patterns first. An empty result means no exclusions.
func effectiveWildcardExcludes(scanCfg *config.Config, req ScanRequest) []string {
	parts := make([]string, 0, 8)
	if scanCfg != nil {
		parts = append(parts, scanCfg.WildcardExclude...)
	}
	parts = append(parts, req.ExcludeSubdomains...)
	// Re-parse through the shared splitter so a single per-scan entry that is
	// itself comma-separated ("dev,staging") is normalized like the env form.
	return config.ParseCommaList(strings.Join(parts, ","))
}

// hostForExclusionMatch reduces a target string (which may be a bare hostname,
// host:port, or full URL) to the lowercase hostname used for exclusion matching,
// with any scheme, userinfo, port, path and trailing dot removed.
func hostForExclusionMatch(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	// Strip a trailing :port. IPv6 literals (bracketed) are left alone;
	// exclusions target DNS names, not IPv6 addresses.
	if !strings.HasPrefix(s, "[") {
		if i := strings.LastIndexByte(s, ':'); i >= 0 {
			s = s[:i]
		}
	}
	return strings.TrimSuffix(s, ".")
}

// subdomainMatchesExclusion reports whether host matches one operator exclusion
// pattern. Matching is case-insensitive and a trailing dot on either side is
// ignored. A pattern containing a glob metacharacter (*, ?, [) is matched with
// path.Match against the full host AND against each dot-separated label, so
// "dev-*" matches the "dev-api" label and "*.internal.example.com" matches the
// whole host. A pattern with no glob metacharacter is a whole-label match: it
// matches when any dot-separated label equals it ("staging" matches
// staging.example.com and api.staging.example.com, but not staginghost.x.com).
func subdomainMatchesExclusion(host, pattern string) bool {
	h := hostForExclusionMatch(host)
	p := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	if h == "" || p == "" {
		return false
	}
	labels := strings.Split(h, ".")
	if strings.ContainsAny(p, "*?[") {
		if ok, err := path.Match(p, h); err == nil && ok {
			return true
		}
		for _, l := range labels {
			if ok, err := path.Match(p, l); err == nil && ok {
				return true
			}
		}
		return false
	}
	for _, l := range labels {
		if l == p {
			return true
		}
	}
	return false
}

// filterExcludedSubdomains returns the subdomains that survive the exclusion
// patterns, plus the number dropped. Order is preserved. Mandatory hosts (the
// operator-supplied target and the authorized root) are always retained even if
// a pattern would match them — an explicit scope decision must never drop the
// host the operator actually asked for.
func filterExcludedSubdomains(subdomains, patterns []string, mandatory ...string) (kept []string, skipped int) {
	if len(patterns) == 0 || len(subdomains) == 0 {
		return subdomains, 0
	}
	mand := make(map[string]bool, len(mandatory))
	for _, m := range mandatory {
		if h := hostForExclusionMatch(m); h != "" {
			mand[h] = true
		}
	}
	kept = make([]string, 0, len(subdomains))
	for _, sub := range subdomains {
		if mand[hostForExclusionMatch(sub)] {
			kept = append(kept, sub)
			continue
		}
		matched := false
		for _, p := range patterns {
			if subdomainMatchesExclusion(sub, p) {
				matched = true
				break
			}
		}
		if matched {
			skipped++
			continue
		}
		kept = append(kept, sub)
	}
	return kept, skipped
}
