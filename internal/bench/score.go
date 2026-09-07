package bench

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// Result is the outcome of running one challenge.
type Result struct {
	Name             string
	Class            string
	Negative         bool // negative control: correct outcome is NO finding of Class
	Solved           bool // handled correctly (positive: found; negative: correctly avoided)
	MatchedFindingID string
	Findings         int
	Elapsed          time.Duration
	TimedOut         bool
	Err              error
}

// Scorecard aggregates challenge results.
type Scorecard struct {
	Results []Result
}

// Total returns the number of challenges run.
func (s Scorecard) Total() int { return len(s.Results) }

// SolvedCount returns the number of challenges solved.
func (s Scorecard) SolvedCount() int {
	n := 0
	for _, r := range s.Results {
		if r.Solved {
			n++
		}
	}
	return n
}

// NegativeCount returns the number of negative-control challenges.
func (s Scorecard) NegativeCount() int {
	n := 0
	for _, r := range s.Results {
		if r.Negative {
			n++
		}
	}
	return n
}

// FalsePositives returns the number of negative-control challenges the scan
// mishandled by reporting the class it was supposed to stay silent on. This is
// the benchmark's precision signal: a scanner that over-reports fails these.
func (s Scorecard) FalsePositives() int {
	n := 0
	for _, r := range s.Results {
		if r.Negative && !r.Solved {
			n++
		}
	}
	return n
}

// ByClass returns solved/total counts per vulnerability class.
func (s Scorecard) ByClass() map[string][2]int {
	out := map[string][2]int{}
	for _, r := range s.Results {
		c := out[r.Class]
		c[1]++
		if r.Solved {
			c[0]++
		}
		out[r.Class] = c
	}
	return out
}

// String renders a human-readable scorecard.
func (s Scorecard) String() string {
	var b strings.Builder
	total := s.Total()
	solved := s.SolvedCount()
	pct := 0.0
	if total > 0 {
		pct = 100 * float64(solved) / float64(total)
	}
	fmt.Fprintf(&b, "Benchmark scorecard: %d/%d solved (%.0f%%)\n", solved, total, pct)
	for _, r := range s.Results {
		status := "FAIL"
		if r.Solved {
			status = "PASS"
		}
		fmt.Fprintf(&b, "  [%s] %-16s %-14s %2d finding(s)  %6.1fs", status, r.Name, r.Class, r.Findings, r.Elapsed.Seconds())
		switch {
		case r.Negative && r.Solved:
			b.WriteString("  (negative: no FP)")
		case r.Negative && !r.Solved:
			fmt.Fprintf(&b, "  FALSE POSITIVE -> %s", r.MatchedFindingID)
		case r.MatchedFindingID != "":
			fmt.Fprintf(&b, "  -> %s", r.MatchedFindingID)
		}
		if r.TimedOut {
			b.WriteString("  (timed out)")
		}
		if r.Err != nil {
			fmt.Fprintf(&b, "  ERROR: %v", r.Err)
		}
		b.WriteByte('\n')
	}
	// Per-class line, sorted for stable output.
	byClass := s.ByClass()
	classes := make([]string, 0, len(byClass))
	for c := range byClass {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	if len(classes) > 0 {
		b.WriteString("By class:")
		for _, c := range classes {
			fmt.Fprintf(&b, " %s %d/%d", c, byClass[c][0], byClass[c][1])
		}
		b.WriteByte('\n')
	}
	if neg := s.NegativeCount(); neg > 0 {
		fmt.Fprintf(&b, "Precision: %d/%d negative controls clean, %d false positive(s)\n", neg-s.FalsePositives(), neg, s.FalsePositives())
	}
	return b.String()
}

// Solved reports whether any finding is of the expected vulnerability class,
// returning the matching finding's ID. This is the deterministic scoring
// primitive — no model involved.
//
// Each challenge app hosts exactly ONE vulnerability, so a finding of the right
// class against it is the intended bug. Endpoint/path precision is deliberately
// NOT required: whether the agent proves the class on /search or / (and whether
// it discovers a specific route) is a separate concern from whether it detects
// the class, which is what this benchmark measures.
func Solved(expectedClass string, findings []reporting.Vulnerability) (bool, string) {
	want := canonicalClass(expectedClass)
	for _, f := range findings {
		if classifyFinding(f) == want {
			return true, f.ID
		}
	}
	return false, ""
}

// classifyFinding maps a finding to a canonical vuln class using its title,
// description, and CWE. It is intentionally self-contained (not tied to the
// reporting package's private classifier) so the benchmark's notion of "right
// class" is explicit and stable.
func classifyFinding(f reporting.Vulnerability) string {
	text := strings.ToLower(f.Title + " " + f.Description)
	// CORS is identified by an UNAMBIGUOUS textual signal (a reflected
	// Access-Control-Allow-Origin / "cross-origin resource sharing" / "CORS
	// misconfiguration"), checked BEFORE the CWE. Agents frequently tag a CORS
	// finding with a GENERIC access-control CWE (e.g. CWE-284, which cweClass
	// maps to idor), so a CWE-first rule would absorb CORS into idor. The CORS
	// wording is far more specific than a generic CWE, and each benchmark app
	// hosts exactly one bug, so this override cannot steal a genuine idor/other
	// finding.
	if isCORSSignal(text) {
		return "cors"
	}
	// Prefer the CWE: it is the authoritative, structured class signal. A finding
	// tagged CWE-1336 is SSTI even when its description also mentions the remote
	// code execution it can escalate to — which would otherwise match the broader
	// "rce" keyword (which precedes "ssti" in classKeywords) and misclassify the
	// finding. Title/description keywords are the fallback for findings that carry
	// no (or an unmapped) CWE.
	if c := cweClass(f.CWE); c != "" {
		return c
	}
	for _, m := range classKeywords {
		for _, kw := range m.keywords {
			if strings.Contains(text, kw) {
				return m.class
			}
		}
	}
	return ""
}

// ClassifyFinding returns the canonical vulnerability class for a scanner
// finding. External benchmark suites use the same classifier as the built-in
// challenges so class scoring cannot drift between the two harnesses.
func ClassifyFinding(f reporting.Vulnerability) string {
	return classifyFinding(f)
}

// CanonicalClass normalizes a vulnerability class label to the benchmark's
// canonical vocabulary.
func CanonicalClass(class string) string {
	return canonicalClass(class)
}

type classMatch struct {
	class    string
	keywords []string
}

// classKeywords maps title/description keywords to canonical classes. Order
// matters only in that the first hit wins; keep the more specific phrases first.
var classKeywords = []classMatch{
	{"xss", []string{"xss", "cross-site scripting", "cross site scripting", "script injection"}},
	// NoSQL must precede sqli: "nosql injection" contains the substring "sql
	// inject", so the sqli row would otherwise misclassify it.
	{"nosqli", []string{"nosql injection", "nosql inject", "nosqli", "nosql", "mongodb injection", "mongo injection", "operator injection", "$ne", "$gt", "$where"}},
	{"sqli", []string{"sql injection", "sqli", "sql inject", "union select", "blind sql"}},
	{"open_redirect", []string{"open redirect", "unvalidated redirect", "url redirect"}},
	{"idor", []string{"idor", "insecure direct object", "bola", "broken object level", "broken access control", "unauthorized access"}},
	{"ssrf", []string{"ssrf", "server-side request forgery", "server side request forgery"}},
	{"rce", []string{"remote code execution", "rce", "command injection", "os command", "code execution"}},
	{"lfi", []string{"local file inclusion", "lfi", "path traversal", "directory traversal"}},
	{"ssti", []string{"ssti", "template injection"}},
	{"xxe", []string{"xxe", "xml external entity"}},
	{"csrf", []string{"csrf", "cross-site request forgery"}},
	{"business_logic", []string{
		"business logic", "logic flaw",
		"negative quantity", "negative price", "negative total", "negative amount",
		"price manipulation", "price tampering", "quantity tampering",
		"store credit", "workflow bypass",
	}},
}

// canonicalClass normalizes a class label to the benchmark's canonical set.
func canonicalClass(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	switch c {
	case "bola", "bfla":
		return "idor"
	case "openredirect", "open-redirect":
		return "open_redirect"
	case "business-logic", "businesslogic", "logic":
		return "business_logic"
	case "nosql", "nosql-injection", "nosql_injection":
		return "nosqli"
	case "cors-misconfiguration", "cors-misconfig", "cors_misconfiguration", "cors misconfiguration":
		return "cors"
	default:
		return c
	}
}

// isCORSSignal reports whether a finding's text unambiguously describes a CORS
// misconfiguration. classifyFinding consults this BEFORE the CWE so a CORS
// finding an agent happened to tag with a generic access-control CWE (e.g.
// CWE-284) is not miscounted as idor. The phrases are CORS-specific — a genuine
// idor/xss/etc. finding does not contain them — so the override is safe.
func isCORSSignal(text string) bool {
	return strings.Contains(text, "cors") ||
		strings.Contains(text, "cross-origin resource sharing") ||
		strings.Contains(text, "access-control-allow-origin")
}

// cweClass maps a CWE identifier to a canonical class, or "" when unmapped.
func cweClass(cwe string) string {
	switch firstDigits(cwe) {
	case "79":
		return "xss"
	case "89":
		return "sqli"
	case "943":
		return "nosqli"
	case "942", "346":
		// CWE-942 (Permissive Cross-domain Policy) / CWE-346 (Origin Validation
		// Error) — the structured signals for a CORS misconfiguration.
		return "cors"
	case "601":
		return "open_redirect"
	case "918":
		return "ssrf"
	case "22":
		return "lfi"
	case "77", "78", "94":
		return "rce"
	case "611":
		return "xxe"
	case "352":
		return "csrf"
	case "1336":
		return "ssti"
	case "284", "285", "639", "862", "863", "566":
		return "idor"
	case "840", "841":
		return "business_logic"
	default:
		return ""
	}
}

// firstDigits returns the first run of digits in s (so "CWE-79" -> "79").
func firstDigits(s string) string {
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			if start == -1 {
				start = i
			}
		} else if start != -1 {
			return s[start:i]
		}
	}
	if start != -1 {
		return s[start:]
	}
	return ""
}
