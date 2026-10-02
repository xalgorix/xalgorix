package web

import (
	"net"
	"net/url"
	"strings"

	"github.com/weppos/publicsuffix-go/publicsuffix"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// wildcardTarget is the normalized view of one user-supplied wildcard-scan
// target. It deliberately separates three concerns that the previous
// implementation conflated with a single string:
//
//   - Host: the bare hostname the user pointed at (no scheme, port, or path).
//     This is the mandatory assessment subject: whatever discovery finds, the
//     exact host the operator typed is scanned.
//   - Root: the registrable domain (public-suffix aware) that organization-wide
//     subdomain discovery runs against. For "www.example.com" that is
//     "example.com"; for "www.example.co.uk" it is "example.co.uk", never
//     "co.uk". Deriving this by trimming the first label (or just "www.") is
//     wrong for multi-label suffixes and dangerous for hosts like "www.com".
//   - Assessment: the exact string the child session receives for the
//     mandatory target. When the operator supplied scheme/port/path context
//     (e.g. "https://www.example.com:8443/app"), it is preserved verbatim so a
//     nonstandard port or required application path is never discarded. When
//     the input was a bare host, it equals Host.
//
// Parse failures and public-suffix-only inputs fail CLOSED: Root falls back to
// Host, so discovery never expands testing to an unauthorized parent domain.
type wildcardTarget struct {
	Raw        string // cleaned user input (whitespace-trimmed; "*" prefix removed)
	Host       string // lowercase bare hostname, no trailing dot
	Root       string // registrable discovery root; == Host when unparseable
	Assessment string // exact assessment string for the mandatory target
}

// wildcardHostOf reduces an inventory entry (bare host, or a URL with scheme /
// port / path) to its lowercase bare hostname for dedupe and scope matching.
// Returns "" when no hostname can be extracted.
func wildcardHostOf(entry string) string {
	s := strings.TrimSpace(strings.ToLower(entry))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip path, query, and fragment.
	for _, cut := range []byte{'/', '?', '#'} {
		if i := strings.IndexByte(s, cut); i >= 0 {
			s = s[:i]
		}
	}
	// Strip userinfo if present.
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	// Split off a port. net.SplitHostPort handles bracketed IPv6; fall back to
	// the last colon only when it is the single colon and a digit follows.
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		s = host
	} else if i := strings.LastIndexByte(s, ':'); i > 0 && i == strings.IndexByte(s, ':') && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
		s = s[:i]
	}
	// Wildcard notation reduces to the domain it names.
	s = strings.TrimPrefix(s, "*.")
	s = strings.Trim(s, ".")
	if s == "" || strings.ContainsAny(s, " \t") {
		return ""
	}
	return s
}

// parseWildcardTarget normalizes one user-supplied wildcard target.
func parseWildcardTarget(raw string) wildcardTarget {
	cleaned := strings.TrimSpace(raw)
	// A leading "*." is wildcard notation for the domain itself; drop it so
	// "*.example.com" behaves exactly like "example.com".
	if strings.HasPrefix(cleaned, "*.") {
		cleaned = strings.TrimSpace(strings.TrimPrefix(cleaned, "*."))
	}
	wt := wildcardTarget{Raw: cleaned}

	// Extract the hostname with url semantics. Prepend a scheme when the input
	// is bare so ports and paths still parse.
	parseInput := cleaned
	if !strings.Contains(parseInput, "://") {
		parseInput = "http://" + parseInput
	}
	host := cleaned
	if u, err := url.Parse(parseInput); err == nil && u.Host != "" {
		host = u.Hostname()
	} else {
		// Malformed input: fall back to conservative text cleanup.
		if i := strings.IndexAny(host, "/?#"); i >= 0 {
			host = host[:i]
		}
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
	}
	wt.Host = strings.ToLower(strings.Trim(host, "."))

	// Registrable root via the public suffix list. IPs and public-suffix-only
	// names fail closed: Root == Host, so discovery enumerates nothing beyond
	// the exact name the operator supplied.
	wt.Root = wt.Host
	if net.ParseIP(wt.Host) == nil {
		if root, err := publicsuffix.Domain(wt.Host); err == nil && root != "" &&
			(strings.EqualFold(wt.Host, root) || strings.HasSuffix(strings.ToLower(wt.Host), "."+strings.ToLower(root))) {
			wt.Root = strings.ToLower(root)
		}
	}

	// The mandatory assessment entry is the user's exact input (minus wildcard
	// notation), preserving any scheme/port/path context. When the input was a
	// bare hostname, Assessment is that hostname.
	wt.Assessment = cleaned
	if wt.Assessment == "" {
		wt.Assessment = wt.Host
	}
	return wt
}

// mergeWildcardInventory guarantees the mandatory assessment subjects survive
// discovery filtering and deduplication:
//
//   - the exact host the operator supplied (with its original scheme/port/path
//     context when provided), and
//   - the authorized registrable root domain.
//
// Entries already present keep their positions (resume index stability), a
// discovered bare-host duplicate of the supplied target is upgraded IN PLACE to
// the richer URL-context entry, and missing mandatory entries are appended.
// Fingerprint-based or discovery-based elision of the original target is
// therefore impossible: the merge is the last word on inventory membership.
func mergeWildcardInventory(discovered []string, wt wildcardTarget) []string {
	out := append([]string(nil), discovered...)
	pos := make(map[string]int, len(out)+2)
	for i, entry := range out {
		if h := wildcardHostOf(entry); h != "" {
			if _, dup := pos[h]; !dup {
				pos[h] = i
			}
		}
	}
	mandatory := make([]string, 0, 2)
	if wt.Host != "" {
		mandatory = append(mandatory, wt.Assessment)
	}
	if rootHost := wildcardHostOf(wt.Root); rootHost != "" && rootHost != wildcardHostOf(wt.Assessment) {
		mandatory = append(mandatory, wt.Root)
	}
	for _, m := range mandatory {
		h := wildcardHostOf(m)
		if h == "" {
			continue
		}
		if idx, ok := pos[h]; ok {
			// Upgrade a bare-host discovery hit to the operator URL-context
			// entry without moving its position.
			if existing := out[idx]; !strings.Contains(existing, "://") && strings.Contains(m, "://") {
				out[idx] = m
			}
			continue
		}
		out = append(out, m)
		pos[h] = len(out) - 1
	}
	return out
}

// vulnFromSummary converts a persisted scan-record finding back into the
// reporting store representation (the inverse of vulnToSummary) so a rebuilt
// parent accumulation context carries the same verified evidence.
func vulnFromSummary(vs VulnSummary) reporting.Vulnerability {
	return reporting.Vulnerability{
		Replaces:           vs.Replaces,
		ID:                 vs.ID,
		Title:              vs.Title,
		Severity:           vs.Severity,
		Target:             vs.Target,
		Endpoint:           vs.Endpoint,
		CVSS:               vs.CVSS,
		CVSSVector:         vs.CVSSVector,
		Description:        vs.Description,
		Impact:             vs.Impact,
		Method:             vs.Method,
		CVE:                vs.CVE,
		CWE:                vs.CWE,
		OWASP:              vs.OWASP,
		TechnicalAnalysis:  vs.TechnicalAnalysis,
		PoCDescription:     vs.PoCDescription,
		PoCScript:          vs.PoCScript,
		Remediation:        vs.Remediation,
		Fix:                vs.Fix,
		ExploitationProof:  vs.ExploitationProof,
		VerificationMethod: vs.VerificationMethod,
		Verified:           vs.Verified,
		Tags:               vs.Tags,
	}
}

// reseedWildcardParentVulnerabilities rebuilds the parent accumulation context
// after an interruption. The in-memory context died with the process; the
// durable truth is each completed child scan record on disk. Verified findings
// are restored so the live counter never regresses on resume and the first
// resumed child is never credited with previously reported findings.
func (s *Server) reseedWildcardParentVulnerabilities(parentCtxID, instanceID string, parentRecord *ScanRecord) int {
	if parentCtxID == "" || parentRecord == nil {
		return 0
	}
	childIDs := make(map[string]bool, len(parentRecord.SubScans))
	for _, child := range parentRecord.SubScans {
		if child.ID == "" || !isFinishedSubScanStatus(child.Status) {
			continue
		}
		childIDs[child.ID] = true
	}
	if len(childIDs) == 0 {
		return 0
	}
	var seed []reporting.Vulnerability
	for _, entry := range s.findAllScanSummaries() {
		if !childIDs[entry.rec.ID] {
			continue
		}
		// A record carrying a different instance id is not one of ours. Empty
		// instance ids (older records) are accepted: the scan id is unique.
		if instanceID != "" && entry.rec.InstanceID != "" && entry.rec.InstanceID != instanceID {
			continue
		}
		for _, vs := range entry.rec.Vulns {
			seed = append(seed, vulnFromSummary(vs))
		}
	}
	reporting.ResetVulnerabilitiesForContext(parentCtxID)
	return reporting.SeedVulnsForContext(parentCtxID, seed)
}

// wildcardChildOutcome maps a child session record to the inventory status
// the parent records for that host. A child that the engine recorded as
// failed (aborted with nothing to show) stays "failed" so unfinished
// assessments remain identifiable; any other completed state counts as a
// finished host assessment. A nil record (session never produced one) is a
// failure.
func wildcardChildOutcome(rec *ScanRecord) string {
	if rec == nil {
		return "failed"
	}
	if strings.EqualFold(strings.TrimSpace(rec.Status), "failed") {
		return "failed"
	}
	return "finished"
}

// isMandatoryWildcardEntry reports whether an inventory entry is one of the
// mandatory assessment subjects for this target (the exact operator-supplied
// host or the authorized registrable root). The explicit wildcard resource cap
// never trims these: the operator asked for this host, so it is assessed even
// when the discovered candidate list exceeds the configured limit.
func isMandatoryWildcardEntry(entry string, wt wildcardTarget) bool {
	h := wildcardHostOf(entry)
	if h == "" {
		return false
	}
	return h == wildcardHostOf(wt.Assessment) || h == wildcardHostOf(wt.Root)
}
