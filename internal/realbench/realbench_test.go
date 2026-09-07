package realbench

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

const testManifest = `{
  "schema_version": 1,
  "name": "test suite",
  "ground_truth_scope": "one documented CVE",
  "targets": [
    {
      "id": "grafana-vulnerable",
      "mode": "vulnerable",
      "product": "Grafana OSS",
      "version": "8.2.6",
      "container": {
        "image_ref": "grafana/grafana:8.2.6@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "default_url": "http://127.0.0.1:3300"
      },
      "expectations": [{
        "id": "CVE-2021-43798",
        "class": "lfi",
        "cwe": "CWE-22",
        "severity": "high",
        "endpoints": ["/public/plugins/"],
        "methods": ["GET"],
        "require_proof": true
      }]
    },
    {
      "id": "grafana-fixed",
      "mode": "fixed-control",
      "product": "Grafana OSS",
      "version": "8.2.7",
      "container": {
        "image_ref": "grafana/grafana:8.2.7@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "default_url": "http://127.0.0.1:3301"
      },
      "control_for": ["CVE-2021-43798"]
    }
  ]
}`

func loadTestSuite(t *testing.T) Suite {
	t.Helper()
	suite, err := Load(strings.NewReader(testManifest))
	if err != nil {
		t.Fatal(err)
	}
	return suite
}

func grafanaFinding(id string, proven bool) reporting.Vulnerability {
	finding := reporting.Vulnerability{
		ID:       id,
		Title:    "Grafana plugin path traversal",
		CWE:      "CWE-22",
		Endpoint: "http://127.0.0.1:3300/public/plugins/alertlist/../../etc/passwd",
		Method:   "GET",
	}
	if proven {
		finding.Tags = []string{reporting.TagExploitProven}
	}
	return finding
}

func TestLoadRejectsUnpinnedImage(t *testing.T) {
	bad := strings.Replace(testManifest, "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", 1)
	if _, err := Load(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "pin container.image_ref") {
		t.Fatalf("expected immutable-image validation error, got %v", err)
	}
}

func TestLoadRejectsMalformedImageDigest(t *testing.T) {
	bad := strings.Replace(testManifest,
		"@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"@sha256:abcd", 1)
	if _, err := Load(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "pin container.image_ref") {
		t.Fatalf("expected full sha256 digest validation error, got %v", err)
	}
}

func TestLoadRejectsNonLoopbackTarget(t *testing.T) {
	bad := strings.Replace(testManifest, "http://127.0.0.1:3300", "https://grafana.example.com", 1)
	if _, err := Load(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback-only validation error, got %v", err)
	}
}

func TestLoadRejectsExpectationWithoutProof(t *testing.T) {
	bad := strings.Replace(testManifest, `"require_proof": true`, `"require_proof": false`, 1)
	if _, err := Load(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "must require exploit proof") {
		t.Fatalf("expected exploit-proof validation error, got %v", err)
	}
}

func TestLoadRejectsTrailingJSONValue(t *testing.T) {
	if _, err := Load(strings.NewReader(testManifest + `{}`)); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("expected trailing JSON validation error, got %v", err)
	}
}

func TestScorePositiveRequiresExploitProof(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")

	miss := Score(suite, target, []reporting.Vulnerability{grafanaFinding("XALG-1", false)})
	if miss.Matched != 0 || len(miss.Expectations[0].UnprovenIDs) != 1 {
		t.Fatalf("unproven candidate must not count as found: %+v", miss)
	}

	found := Score(suite, target, []reporting.Vulnerability{grafanaFinding("XALG-1", true)})
	if found.Matched != 1 || found.TargetedRecall != 1 || found.Expectations[0].FindingID != "XALG-1" {
		t.Fatalf("expected proven finding to match: %+v", found)
	}
}

func TestScoreAllowsOmittedOptionalMethodForExactSignature(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	finding := grafanaFinding("XALG-1", true)
	finding.Method = ""
	finding.CVE = "CVE-2021-43798"

	result := Score(suite, target, []reporting.Vulnerability{finding})
	if result.Matched != 1 || result.TargetedRecall != 1 {
		t.Fatalf("empty optional method must not erase an exact proven signature: %+v", result)
	}

	finding.Method = "POST"
	result = Score(suite, target, []reporting.Vulnerability{finding})
	if result.Matched != 0 {
		t.Fatalf("an explicitly wrong method must still fail the signature: %+v", result)
	}
}

func TestScoreExactCVEAllowsOmittedClassMetadata(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	finding := reporting.Vulnerability{
		ID:       "XALG-1",
		Title:    "CVE-2021-43798: Unauthenticated arbitrary file read",
		CVE:      "CVE-2021-43798",
		Endpoint: "http://127.0.0.1:3300/public/plugins/alertlist/../../etc/passwd",
		Verified: true,
	}

	result := Score(suite, target, []reporting.Vulnerability{finding})
	if result.Matched != 1 || result.TargetedRecall != 1 {
		t.Fatalf("exact CVE with matching endpoint and proof must survive omitted CWE/method metadata: %+v", result)
	}

	finding.Endpoint = "http://127.0.0.1:3300/api/health"
	result = Score(suite, target, []reporting.Vulnerability{finding})
	if result.Matched != 0 {
		t.Fatalf("exact CVE must not bypass the endpoint signature: %+v", result)
	}
}

func TestScoreCVETextDoesNotMatchAnotherIdentifier(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	finding := reporting.Vulnerability{
		ID:       "XALG-1",
		Title:    "CVE-2021-43799: Different issue",
		CVE:      "CVE-2021-43799",
		Endpoint: "http://127.0.0.1:3300/public/plugins/alertlist/file",
		Verified: true,
	}

	result := Score(suite, target, []reporting.Vulnerability{finding})
	if result.Matched != 0 {
		t.Fatalf("a different CVE identifier must not satisfy the expectation: %+v", result)
	}
}

func TestScoreTracksDuplicatesAndLeavesUnknownsUnclassified(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	unknown := reporting.Vulnerability{ID: "XALG-3", Title: "Different issue", CWE: "CWE-79", Endpoint: "/login", Method: "GET"}
	result := Score(suite, target, []reporting.Vulnerability{
		grafanaFinding("XALG-1", true),
		grafanaFinding("XALG-2", true),
		unknown,
	})
	if result.Matched != 1 || result.DuplicateFindings != 1 {
		t.Fatalf("expected one match plus one duplicate: %+v", result)
	}
	if len(result.UnclassifiedFindings) != 1 || result.UnclassifiedFindings[0] != "XALG-3" {
		t.Fatalf("unknown real-product finding must remain unclassified: %+v", result.UnclassifiedFindings)
	}
}

func TestFixedControlCountsMatchingSignatureAsRegression(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-fixed")
	result := Score(suite, target, []reporting.Vulnerability{grafanaFinding("XALG-1", true)})
	if result.ControlRegressions != 1 || result.Matched != 1 {
		t.Fatalf("expected a fixed-control regression: %+v", result)
	}
}

func TestScoreRejectsExpectedEndpointEmbeddedInAnotherRoute(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	finding := grafanaFinding("XALG-1", true)
	finding.Endpoint = "http://127.0.0.1:3300/redirect/public/plugins/alertlist/file"
	result := Score(suite, target, []reporting.Vulnerability{finding})
	if result.Matched != 0 {
		t.Fatalf("embedded endpoint must not satisfy the expected route family: %+v", result)
	}
}

func TestAggregateExposesIntermittentRecall(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	results := []Result{
		Score(suite, target, []reporting.Vulnerability{grafanaFinding("XALG-1", true)}),
		Score(suite, target, nil),
	}
	agg, err := Aggregate(results)
	if err != nil {
		t.Fatal(err)
	}
	if agg.MeanTargetedRecall != 0.5 || agg.MinimumTargetedRecall != 0 || agg.MaximumTargetedRecall != 1 {
		t.Fatalf("unexpected recall distribution: %+v", agg)
	}
	if agg.ExpectationsFoundAnyRun != 1 || agg.ExpectationsFoundEveryRun != 0 || agg.Stable {
		t.Fatalf("intermittent finding must not be stable: %+v", agg)
	}
	if len(agg.Expectations) != 1 || agg.Expectations[0].Matches != 1 || agg.Expectations[0].MatchRate != 0.5 {
		t.Fatalf("unexpected per-expectation stability: %+v", agg.Expectations)
	}
}

func TestAggregateTracksControlRegressionRuns(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-fixed")
	results := []Result{
		Score(suite, target, nil),
		Score(suite, target, []reporting.Vulnerability{grafanaFinding("XALG-1", true)}),
	}
	agg, err := Aggregate(results)
	if err != nil {
		t.Fatal(err)
	}
	if agg.ControlRunsWithRegressions != 1 || agg.Stable {
		t.Fatalf("expected one unstable control regression run: %+v", agg)
	}
}

func TestAggregateRejectsMixedTargets(t *testing.T) {
	suite := loadTestSuite(t)
	vulnerable, _ := suite.Target("grafana-vulnerable")
	fixed, _ := suite.Target("grafana-fixed")
	if _, err := Aggregate([]Result{Score(suite, vulnerable, nil), Score(suite, fixed, nil)}); err == nil {
		t.Fatal("expected mixed-target aggregation error")
	}
}
