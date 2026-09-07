package realbench

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/bench"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

var cveIdentifierPattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

// ExpectationResult records how one documented vulnerability scored.
type ExpectationResult struct {
	ExpectationID string   `json:"expectation_id"`
	Class         string   `json:"class"`
	Matched       bool     `json:"matched"`
	FindingID     string   `json:"finding_id,omitempty"`
	DuplicateIDs  []string `json:"duplicate_ids,omitempty"`
	UnprovenIDs   []string `json:"unproven_candidate_ids,omitempty"`
}

// Result is an honest, target-scoped score. Unmatched findings are not called
// false positives because a targeted CVE corpus is not a complete inventory of
// every vulnerability in a real product.
type Result struct {
	Suite                string              `json:"suite"`
	TargetID             string              `json:"target_id"`
	Mode                 string              `json:"mode"`
	Product              string              `json:"product"`
	Version              string              `json:"version"`
	Expected             int                 `json:"expected"`
	Matched              int                 `json:"matched"`
	TargetedRecall       float64             `json:"targeted_recall"`
	ControlRegressions   int                 `json:"control_regressions"`
	DuplicateFindings    int                 `json:"duplicate_findings"`
	UnclassifiedFindings []string            `json:"unclassified_finding_ids,omitempty"`
	Expectations         []ExpectationResult `json:"expectations"`
}

// Score matches scanner findings to the documented expectations for target.
func Score(suite Suite, target Target, findings []reporting.Vulnerability) Result {
	expected := suite.ExpectationsFor(target)
	result := Result{
		Suite:        suite.Name,
		TargetID:     target.ID,
		Mode:         target.Mode,
		Product:      target.Product,
		Version:      target.Version,
		Expected:     len(expected),
		Expectations: make([]ExpectationResult, 0, len(expected)),
	}
	consumed := make(map[int]struct{})

	for _, expectation := range expected {
		row := ExpectationResult{
			ExpectationID: expectation.ID,
			Class:         bench.CanonicalClass(expectation.Class),
		}
		var candidates []int
		for i, finding := range findings {
			if signatureMatches(expectation, finding) {
				candidates = append(candidates, i)
			}
		}

		for _, i := range candidates {
			finding := findings[i]
			consumed[i] = struct{}{}
			if target.Mode == ModeVulnerable && expectation.RequireProof && !hasProof(finding) {
				row.UnprovenIDs = append(row.UnprovenIDs, finding.ID)
				continue
			}
			if !row.Matched {
				row.Matched = true
				row.FindingID = finding.ID
				continue
			}
			row.DuplicateIDs = append(row.DuplicateIDs, finding.ID)
			result.DuplicateFindings++
		}

		if row.Matched {
			result.Matched++
		}
		result.Expectations = append(result.Expectations, row)
	}

	for i, finding := range findings {
		if _, ok := consumed[i]; !ok {
			result.UnclassifiedFindings = append(result.UnclassifiedFindings, finding.ID)
		}
	}
	sort.Strings(result.UnclassifiedFindings)
	if result.Expected > 0 {
		result.TargetedRecall = float64(result.Matched) / float64(result.Expected)
	}
	if target.Mode == ModeFixedControl {
		result.ControlRegressions = result.Matched
	}
	return result
}

func signatureMatches(expected Expectation, finding reporting.Vulnerability) bool {
	exactCVE := findingMatchesExpectedCVE(expected.ID, finding)
	if !exactCVE && bench.ClassifyFinding(finding) != bench.CanonicalClass(expected.Class) {
		return false
	}
	// An exact CVE identifier is a stronger structured signature than optional
	// class/CWE metadata. Models sometimes omit cwe_id even after reporting the
	// precise CVE with a proof-bearing endpoint; that must not turn a true finding
	// into a benchmark miss. Endpoint, method (when explicit), and proof checks
	// still apply below, so a bare or unrelated CVE mention cannot score.
	if !exactCVE && expected.CWE != "" && digits(finding.CWE) != digits(expected.CWE) {
		return false
	}
	// report_vulnerability deliberately keeps method optional so a fully proven
	// finding is not discarded when a model omits metadata. Treat an explicitly
	// reported, wrong method as a signature mismatch, but do not turn an empty
	// optional field into a false benchmark miss when class, CWE, endpoint, and
	// exploit proof all match. This also mirrors how a human triager handles an
	// unambiguous URL-based PoC whose prose shows the request verb.
	if len(expected.Methods) > 0 && strings.TrimSpace(finding.Method) != "" &&
		!containsFold(expected.Methods, finding.Method) {
		return false
	}
	path := endpointPath(finding.Endpoint)
	if path == "" {
		path = endpointPath(finding.Target)
	}
	for _, candidate := range expected.Endpoints {
		if endpointContains(path, candidate) {
			return true
		}
	}
	return false
}

func findingMatchesExpectedCVE(expectedID string, finding reporting.Vulnerability) bool {
	want := strings.ToUpper(strings.TrimSpace(expectedID))
	if match := cveIdentifierPattern.FindString(want); match == "" || !strings.EqualFold(match, want) {
		return false
	}
	for _, value := range []string{finding.CVE, finding.Title, finding.Description} {
		for _, candidate := range cveIdentifierPattern.FindAllString(value, -1) {
			if strings.EqualFold(candidate, want) {
				return true
			}
		}
	}
	return false
}

func endpointPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Path != "" {
		raw = parsed.Path
	}
	return strings.ToLower(strings.TrimSuffix(raw, "/"))
}

func endpointContains(actual, expected string) bool {
	expected = endpointPath(expected)
	if actual == "" || expected == "" {
		return false
	}
	return actual == expected || strings.HasPrefix(actual, expected+"/")
}

func containsFold(values []string, value string) bool {
	for _, candidate := range values {
		if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(value)) {
			return true
		}
	}
	return false
}

func hasProof(finding reporting.Vulnerability) bool {
	if finding.Verified {
		return true
	}
	for _, tag := range finding.Tags {
		if tag == reporting.TagVerified || tag == reporting.TagExploitProven {
			return true
		}
	}
	return false
}

func digits(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// String renders a compact scorecard suitable for benchmark logs.
func (r Result) String() string {
	var b strings.Builder
	if r.Mode == ModeFixedControl {
		fmt.Fprintf(&b, "Real-world control: %s %s — %d/%d known signatures absent\n",
			r.Product, r.Version, r.Expected-r.ControlRegressions, r.Expected)
	} else {
		fmt.Fprintf(&b, "Real-world targeted recall: %s %s — %d/%d (%.0f%%)\n",
			r.Product, r.Version, r.Matched, r.Expected, 100*r.TargetedRecall)
	}
	for _, row := range r.Expectations {
		status := "MISS"
		if r.Mode == ModeFixedControl {
			status = "CLEAN"
			if row.Matched {
				status = "REGRESSION"
			}
		} else if row.Matched {
			status = "FOUND"
		}
		fmt.Fprintf(&b, "  [%s] %s (%s)", status, row.ExpectationID, row.Class)
		if row.FindingID != "" {
			fmt.Fprintf(&b, " -> %s", row.FindingID)
		}
		if len(row.DuplicateIDs) > 0 {
			fmt.Fprintf(&b, " duplicates=%s", strings.Join(row.DuplicateIDs, ","))
		}
		if len(row.UnprovenIDs) > 0 {
			fmt.Fprintf(&b, " unproven=%s", strings.Join(row.UnprovenIDs, ","))
		}
		b.WriteByte('\n')
	}
	if len(r.UnclassifiedFindings) > 0 {
		fmt.Fprintf(&b, "Unclassified findings (manual triage; not counted as false positives): %s\n",
			strings.Join(r.UnclassifiedFindings, ","))
	}
	if r.DuplicateFindings > 0 {
		fmt.Fprintf(&b, "Duplicate findings: %d\n", r.DuplicateFindings)
	}
	return b.String()
}
