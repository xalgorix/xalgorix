// Package realbench scores Xalgorix findings against a version-pinned corpus
// of vulnerabilities in real open-source products.
//
// Unlike the built-in synthetic challenge suite, a real product may contain
// undisclosed or out-of-scope vulnerabilities. The manifest therefore defines
// a targeted CVE corpus: recall is calculated only for documented expectations,
// while unmatched findings are left unclassified rather than mislabeled as
// false positives. Patched-version controls provide the false-positive signal.
package realbench

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/bench"
)

var (
	targetIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	imageDigestPattern = regexp.MustCompile(`^[^\s@]+@sha256:[a-fA-F0-9]{64}$`)
)

const SchemaVersion = 1

const (
	ModeVulnerable   = "vulnerable"
	ModeFixedControl = "fixed-control"
)

// Suite is a targeted real-world vulnerability corpus.
type Suite struct {
	SchemaVersion    int      `json:"schema_version"`
	Name             string   `json:"name"`
	GroundTruthScope string   `json:"ground_truth_scope"`
	Targets          []Target `json:"targets"`
}

// Target describes one pinned product release and how it participates in the
// corpus. Vulnerable targets carry Expectations; fixed controls reference the
// expectation IDs they must no longer exhibit.
type Target struct {
	ID               string        `json:"id"`
	Mode             string        `json:"mode"`
	Product          string        `json:"product"`
	Version          string        `json:"version"`
	SourceRepository string        `json:"source_repository,omitempty"`
	SourceRef        string        `json:"source_ref,omitempty"`
	Container        Container     `json:"container"`
	Advisories       []string      `json:"advisories,omitempty"`
	Expectations     []Expectation `json:"expectations,omitempty"`
	ControlFor       []string      `json:"control_for,omitempty"`
}

// Container records the immutable deployment used for a benchmark target.
type Container struct {
	ImageRef   string `json:"image_ref"`
	DefaultURL string `json:"default_url"`
	HealthPath string `json:"health_path,omitempty"`
}

// Expectation is one documented vulnerability that a scan should prove.
type Expectation struct {
	ID           string   `json:"id"`
	Class        string   `json:"class"`
	CWE          string   `json:"cwe"`
	Severity     string   `json:"severity,omitempty"`
	Endpoints    []string `json:"endpoints"`
	Methods      []string `json:"methods,omitempty"`
	RequireProof bool     `json:"require_proof"`
}

// Load parses and validates a suite manifest.
func Load(r io.Reader) (Suite, error) {
	var suite Suite
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&suite); err != nil {
		return Suite{}, fmt.Errorf("decode real-world benchmark manifest: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Suite{}, fmt.Errorf("decode real-world benchmark manifest: multiple JSON values")
		}
		return Suite{}, fmt.Errorf("decode real-world benchmark manifest: trailing data: %w", err)
	}
	if err := suite.Validate(); err != nil {
		return Suite{}, err
	}
	return suite, nil
}

// LoadFile parses a suite manifest from path.
func LoadFile(path string) (Suite, error) {
	f, err := os.Open(path)
	if err != nil {
		return Suite{}, fmt.Errorf("open real-world benchmark manifest: %w", err)
	}
	defer f.Close()
	return Load(f)
}

// Validate rejects ambiguous manifests before an expensive agent run starts.
func (s Suite) Validate() error {
	if s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("real-world benchmark schema_version must be %d", SchemaVersion)
	}
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("real-world benchmark name is required")
	}
	if strings.TrimSpace(s.GroundTruthScope) == "" {
		return fmt.Errorf("real-world benchmark ground_truth_scope is required")
	}
	if len(s.Targets) == 0 {
		return fmt.Errorf("real-world benchmark must contain at least one target")
	}

	targetIDs := make(map[string]struct{}, len(s.Targets))
	expectations := make(map[string]Expectation)
	for i, target := range s.Targets {
		if err := validateTarget(target); err != nil {
			return fmt.Errorf("target %d: %w", i, err)
		}
		if _, exists := targetIDs[target.ID]; exists {
			return fmt.Errorf("duplicate target id %q", target.ID)
		}
		targetIDs[target.ID] = struct{}{}
		for _, expected := range target.Expectations {
			if _, exists := expectations[expected.ID]; exists {
				return fmt.Errorf("duplicate expectation id %q", expected.ID)
			}
			expectations[expected.ID] = expected
		}
	}

	for _, target := range s.Targets {
		for _, id := range target.ControlFor {
			if _, exists := expectations[id]; !exists {
				return fmt.Errorf("target %q controls unknown expectation %q", target.ID, id)
			}
		}
	}
	return nil
}

func validateTarget(target Target) error {
	if strings.TrimSpace(target.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if !targetIDPattern.MatchString(target.ID) {
		return fmt.Errorf("target id %q must contain only lowercase letters, digits, dots, underscores, and hyphens", target.ID)
	}
	if strings.TrimSpace(target.Product) == "" || strings.TrimSpace(target.Version) == "" {
		return fmt.Errorf("product and version are required for %q", target.ID)
	}
	if !imageDigestPattern.MatchString(strings.TrimSpace(target.Container.ImageRef)) {
		return fmt.Errorf("target %q must pin container.image_ref by sha256 digest", target.ID)
	}
	if err := ValidateLoopbackURL(target.Container.DefaultURL); err != nil {
		return fmt.Errorf("target %q container.default_url: %w", target.ID, err)
	}

	switch target.Mode {
	case ModeVulnerable:
		if len(target.Expectations) == 0 {
			return fmt.Errorf("vulnerable target %q needs at least one expectation", target.ID)
		}
		if len(target.ControlFor) > 0 {
			return fmt.Errorf("vulnerable target %q cannot set control_for", target.ID)
		}
	case ModeFixedControl:
		if len(target.ControlFor) == 0 {
			return fmt.Errorf("fixed control %q needs control_for", target.ID)
		}
		if len(target.Expectations) > 0 {
			return fmt.Errorf("fixed control %q cannot define expectations", target.ID)
		}
	default:
		return fmt.Errorf("target %q has unsupported mode %q", target.ID, target.Mode)
	}

	for _, expected := range target.Expectations {
		if strings.TrimSpace(expected.ID) == "" || strings.TrimSpace(expected.Class) == "" || strings.TrimSpace(expected.CWE) == "" {
			return fmt.Errorf("target %q expectations require id, class, and cwe", target.ID)
		}
		if bench.CanonicalClass(expected.Class) == "" {
			return fmt.Errorf("target %q expectation %q has an empty class", target.ID, expected.ID)
		}
		if len(expected.Endpoints) == 0 {
			return fmt.Errorf("target %q expectation %q needs at least one endpoint", target.ID, expected.ID)
		}
		if !expected.RequireProof {
			return fmt.Errorf("target %q expectation %q must require exploit proof", target.ID, expected.ID)
		}
	}
	return nil
}

// ValidateLoopbackURL keeps active real-product benchmarks confined to the
// operator's machine. A manifest may describe real software, but the runner is
// deliberately not a mechanism for probing a public deployment.
func ValidateLoopbackURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("must be a valid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("must use http or https")
	}
	if parsed.User != nil {
		return fmt.Errorf("must not include credentials")
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("must resolve explicitly to a loopback host")
	}
	return nil
}

// Target returns a target by ID.
func (s Suite) Target(id string) (Target, bool) {
	for _, target := range s.Targets {
		if target.ID == id {
			return target, true
		}
	}
	return Target{}, false
}

// ExpectationsFor returns the positive expectations relevant to target.
func (s Suite) ExpectationsFor(target Target) []Expectation {
	if target.Mode == ModeVulnerable {
		return append([]Expectation(nil), target.Expectations...)
	}
	wanted := make(map[string]struct{}, len(target.ControlFor))
	for _, id := range target.ControlFor {
		wanted[id] = struct{}{}
	}
	var out []Expectation
	for _, candidate := range s.Targets {
		for _, expected := range candidate.Expectations {
			if _, ok := wanted[expected.ID]; ok {
				out = append(out, expected)
			}
		}
	}
	return out
}
