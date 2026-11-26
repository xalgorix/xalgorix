package web

import (
	"reflect"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func TestSubdomainMatchesExclusion(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		// whole-label (plain word)
		{"staging.example.com", "staging", true},
		{"api.staging.example.com", "staging", true},
		{"staging.example.com", "STAGING", true},      // case-insensitive
		{"staginghost.example.com", "staging", false}, // not a whole label
		{"example.com", "staging", false},
		{"dev.example.com", "dev", true},
		// label glob
		{"dev-api.example.com", "dev-*", true},
		{"api-qa.example.com", "*-qa", true},
		{"apidev.example.com", "*dev", true}, // a label ending in "dev"
		{"production.example.com", "*dev", false},
		// full-host glob
		{"a.internal.example.com", "*.internal.example.com", true},
		{"a.b.internal.example.com", "*.internal.example.com", true},
		{"internal.example.com", "*.internal.example.com", false}, // needs a left label
		// trailing dot in the pattern (customer's informal "staging.")
		{"staging.example.com", "staging.", true},
		// host carrying scheme/port/path still matches on the hostname
		{"https://staging.example.com:8443/app", "staging", true},
		// empties
		{"example.com", "", false},
		{"", "staging", false},
	}
	for _, c := range cases {
		if got := subdomainMatchesExclusion(c.host, c.pattern); got != c.want {
			t.Errorf("subdomainMatchesExclusion(%q,%q)=%v want %v", c.host, c.pattern, got, c.want)
		}
	}
}

func TestFilterExcludedSubdomains(t *testing.T) {
	subs := []string{
		"www.example.com",
		"dev.example.com",
		"staging.example.com",
		"api.example.com",
		"api-qa.example.com",
		"admin.internal.example.com",
	}
	patterns := []string{"dev", "staging", "*-qa", "*.internal.example.com"}
	// dev.example.com matches "dev" but is mandatory, so it must survive.
	kept, skipped := filterExcludedSubdomains(subs, patterns, 0, nil, "dev.example.com")
	wantKept := []string{"www.example.com", "dev.example.com", "api.example.com"}
	if !reflect.DeepEqual(kept, wantKept) {
		t.Fatalf("kept=%v want %v", kept, wantKept)
	}
	if skipped != 3 {
		t.Fatalf("skipped=%d want 3", skipped)
	}
}

// On a resumed inventory the consumed prefix and started hosts are never
// filtered, so the resume index still points at the same host; only unstarted
// hosts past it follow the patterns.
func TestFilterExcludedSubdomains_KeepsConsumedPrefixAndStartedHosts(t *testing.T) {
	subs := []string{
		"www.example.com",
		"dev.example.com",     // consumed; legacy child entry with no id or start time
		"api.example.com",     // consumed
		"staging.example.com", // past the index, child with an id
		"dev-api.example.com", // past the index, child with a start time only
		"dev-web.example.com", // past the index, never started
		"shop.example.com",
	}
	existing := []SubScanSummary{
		{Target: "dev.example.com", Status: "finished"},
		{ID: "child-staging", Target: "staging.example.com", Status: "running"},
		{Target: "dev-api.example.com", Status: "stopped", StartedAt: "2026-01-01T00:00:00Z"},
		{Target: "dev-web.example.com", Status: "pending"},
	}
	kept, skipped := filterExcludedSubdomains(subs, []string{"dev", "staging", "dev-*"}, 3, existing)
	want := []string{"www.example.com", "dev.example.com", "api.example.com", "staging.example.com", "dev-api.example.com", "shop.example.com"}
	if !reflect.DeepEqual(kept, want) || skipped != 1 {
		t.Fatalf("kept=%v skipped=%d, want %v skipped=1", kept, skipped, want)
	}
	if !reflect.DeepEqual(kept[:3], subs[:3]) {
		t.Fatalf("consumed prefix changed: %v", kept[:3])
	}
}

func TestFilterExcludedSubdomains_NoPatternsIsPassthrough(t *testing.T) {
	subs := []string{"a.example.com", "b.example.com"}
	kept, skipped := filterExcludedSubdomains(subs, nil, 0, nil)
	if skipped != 0 || !reflect.DeepEqual(kept, subs) {
		t.Fatalf("passthrough failed: kept=%v skipped=%d", kept, skipped)
	}
}

func TestEffectiveWildcardExcludes_MergesConfigAndRequest(t *testing.T) {
	cfg := &config.Config{WildcardExclude: []string{"staging"}}
	req := ScanRequest{ExcludeSubdomains: []string{"dev,*-qa", "  Internal  "}}
	got := effectiveWildcardExcludes(cfg, req)
	want := []string{"staging", "dev", "*-qa", "internal"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want %v", got, want)
	}
}

func TestEffectiveWildcardExcludes_Empty(t *testing.T) {
	if got := effectiveWildcardExcludes(&config.Config{}, ScanRequest{}); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
	if got := effectiveWildcardExcludes(nil, ScanRequest{}); got != nil {
		t.Fatalf("want nil for nil cfg, got %v", got)
	}
}
