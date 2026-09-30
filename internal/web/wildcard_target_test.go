package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// ─────────────────────────────────────────────────────────────────────────────
// Target normalization (public-suffix aware discovery root + mandatory target)
// ─────────────────────────────────────────────────────────────────────────────

func TestParseWildcardTarget_RegistrableRoot(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		host, root string
	}{
		{"www prefix resolves to registrable root", "www.example.com", "www.example.com", "example.com"},
		{"multi-label public suffix", "www.example.co.uk", "www.example.co.uk", "example.co.uk"},
		{"bare root is its own root", "example.com", "example.com", "example.com"},
		{"wildcard notation enumerates the root", "*.example.com", "example.com", "example.com"},
		{"deep subdomain still enumerates the root", "a.b.example.com", "a.b.example.com", "example.com"},
		{"public-suffix-only input fails closed", "com", "com", "com"},
		{"www on a public-suffix-like host does NOT expand", "www.com", "www.com", "www.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wt := parseWildcardTarget(tc.in)
			if wt.Host != tc.host {
				t.Fatalf("Host = %q, want %q", wt.Host, tc.host)
			}
			if wt.Root != tc.root {
				t.Fatalf("Root = %q, want %q (input %q)", wt.Root, tc.root, tc.in)
			}
		})
	}
}

func TestParseWildcardTarget_PreservesURLContext(t *testing.T) {
	wt := parseWildcardTarget("https://www.example.com:8443/app")
	if wt.Host != "www.example.com" {
		t.Fatalf("Host = %q, want www.example.com", wt.Host)
	}
	if wt.Root != "example.com" {
		t.Fatalf("Root = %q, want example.com", wt.Root)
	}
	if wt.Assessment != "https://www.example.com:8443/app" {
		t.Fatalf("Assessment = %q, want the original URL verbatim", wt.Assessment)
	}

	// Port without scheme must not be swallowed into the hostname.
	wt = parseWildcardTarget("www.example.com:9000")
	if wt.Host != "www.example.com" {
		t.Fatalf("Host = %q, want www.example.com (port must not leak into Host)", wt.Host)
	}
	if wt.Assessment != "www.example.com:9000" {
		t.Fatalf("Assessment = %q, want the original host:port verbatim", wt.Assessment)
	}

	// Bare hostname: assessment is exactly that hostname.
	wt = parseWildcardTarget("  WWW.Example.COM ")
	if wt.Host != "www.example.com" || wt.Assessment != "WWW.Example.COM" {
		t.Fatalf("normalized host = %q, assessment = %q", wt.Host, wt.Assessment)
	}
}

func TestParseWildcardTarget_IPFailsClosed(t *testing.T) {
	for _, in := range []string{"93.184.216.34", "93.184.216.34:8080"} {
		wt := parseWildcardTarget(in)
		if wt.Root != wt.Host {
			t.Fatalf("input %q: Root = %q must not expand past Host = %q for an IP", in, wt.Root, wt.Host)
		}
	}
}

func TestWildcardHostOf(t *testing.T) {
	cases := map[string]string{
		"api.example.com":                   "api.example.com",
		"https://api.example.com":           "api.example.com",
		"http://api.example.com:8080/x?y=1": "api.example.com",
		"API.Example.COM.":                  "api.example.com",
		"*.example.com":                     "example.com", // wildcard notation names the root itself '*' is not stripped here; scope matching uses registrable roots
		"":                                  "",
		"not a host":                        "not a host", // spaces rejected
	}
	for in, want := range cases {
		if got := wildcardHostOf(in); got != want {
			// "not a host" contains a space → rejected to ""
			if in == "not a host" && got == "" {
				continue
			}
			t.Errorf("wildcardHostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Mandatory inventory merge
// ─────────────────────────────────────────────────────────────────────────────

func TestMergeWildcardInventory_AlwaysIncludesOriginalTargetAndRoot(t *testing.T) {
	wt := parseWildcardTarget("www.example.com")
	got := mergeWildcardInventory([]string{"api.example.com", "admin.example.com"}, wt)
	sort.Strings(got)
	want := []string{"admin.example.com", "api.example.com", "example.com", "www.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("inventory = %v, want %v", got, want)
	}
}

func TestMergeWildcardInventory_EmptyDiscoveryStillAssesses(t *testing.T) {
	wt := parseWildcardTarget("www.example.com")
	got := mergeWildcardInventory(nil, wt)
	if len(got) != 2 || got[0] != "www.example.com" || got[1] != "example.com" {
		t.Fatalf("inventory = %v, want [www.example.com example.com]", got)
	}
}

func TestMergeWildcardInventory_BareRootTargetYieldsSingleMandatory(t *testing.T) {
	wt := parseWildcardTarget("example.com")
	got := mergeWildcardInventory([]string{"api.example.com"}, wt)
	if len(got) != 2 || got[0] != "api.example.com" || got[1] != "example.com" {
		t.Fatalf("inventory = %v, want [api.example.com example.com]", got)
	}
}

func TestMergeWildcardInventory_UpgradesBareHostToURLContext(t *testing.T) {
	wt := parseWildcardTarget("https://www.example.com:8443/app")
	got := mergeWildcardInventory([]string{"api.example.com", "www.example.com"}, wt)
	if len(got) != 3 {
		t.Fatalf("inventory = %v, want 3 entries", got)
	}
	if got[1] != "https://www.example.com:8443/app" {
		t.Fatalf("bare-host discovery hit must be upgraded in place to the operator URL context, got %q", got[1])
	}
}

func TestMergeWildcardInventory_OrderStableForResume(t *testing.T) {
	// A resume rebuilds its inventory and must not shift persisted sub-indexes:
	// existing entries keep their positions, missing mandatory entries append.
	wt := parseWildcardTarget("www.example.com")
	existing := []string{"api.example.com", "www.example.com", "admin.example.com"}
	got := mergeWildcardInventory(existing, wt)
	if got[0] != "api.example.com" || got[1] != "www.example.com" || got[2] != "admin.example.com" {
		t.Fatalf("existing order changed: %v", got)
	}
	if got[3] != "example.com" {
		t.Fatalf("missing root must be appended last, got %v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery-source aggregation
// ─────────────────────────────────────────────────────────────────────────────

func TestCollectSubdomains_AggregatesAllSources(t *testing.T) {
	s := newTestServer(t, nil)
	dir := t.TempDir()
	// A "preferred" live list that is a SUBSET of the passive lists: the
	// existence of live_subdomains.txt must not mask the other sources.
	if err := os.WriteFile(filepath.Join(dir, "live_subdomains.txt"), []byte("api.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "all_subdomains.txt"), []byte("api.example.com\nadmin.example.com\nstaging.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "passive_subfinder.txt"), []byte("www.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := s.collectSubdomains(dir, "example.com", "")
	sort.Strings(got)
	want := []string{"admin.example.com", "api.example.com", "staging.example.com", "www.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("aggregated = %v, want %v", got, want)
	}
}

func TestCollectSubdomains_ScopeRestrictedToRegistrableRoot(t *testing.T) {
	s := newTestServer(t, nil)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "all_subdomains.txt"),
		[]byte("api.example.co.uk\nother.example.com\nnotexample.co.uk\nexample.co.uk\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := s.collectSubdomains(dir, "example.co.uk", "")
	if len(got) != 2 {
		t.Fatalf("got %v, want exactly api.example.co.uk + example.co.uk", got)
	}
	sort.Strings(got)
	if got[0] != "api.example.co.uk" || got[1] != "example.co.uk" {
		t.Fatalf("got %v", got)
	}
}

func TestCollectSubdomains_EmptyRootYieldsNothing(t *testing.T) {
	s := newTestServer(t, nil)
	if got := s.collectSubdomains(t.TempDir(), "", ""); got != nil {
		t.Fatalf("empty discovery root must fail closed, got %v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery + child instructions
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildDiscoveryInstruction_UsesProvidedRegistrableRoot(t *testing.T) {
	instr := buildDiscoveryInstruction("example.co.uk", "", scanctx.RequestRatePolicy{})
	if !strings.Contains(instr, "subfinder -d example.co.uk") {
		t.Fatal("discovery instruction must enumerate the registrable root")
	}
	passive := buildPassiveDiscoveryInstruction("example.co.uk")
	if !strings.Contains(passive, "subfinder -d example.co.uk") {
		t.Fatal("passive discovery instruction must enumerate the registrable root")
	}
}

func TestWildcardChildInstruction_SharesStandaloneMethodology(t *testing.T) {
	child := buildSubdomainScanInstruction("api.example.com", "example.com", "", false)
	single := buildAutonomousInstruction("api.example.com", "", false)
	// Deterministic parity markers: the full methodology core (skills,
	// verification standards, auth guidance, false-positive gates) must be
	// present in BOTH because they render from one shared implementation.
	for _, marker := range []string{
		"IDOR (Insecure Direct Object Reference) — REQUIRES TWO ACCOUNTS",
		"FALSE POSITIVE REJECTION LIST",
		"SELF-CRITIQUE BEFORE REPORTING",
		"NATIVE BROWSER-BASED TESTING",
		"agentmail",
		"SAFE EXPLOITATION RULES",
		"UNIVERSAL EMAIL USAGE",
		"browser_action",
	} {
		if !strings.Contains(child, marker) {
			t.Errorf("wildcard child instruction is missing standalone methodology marker %q", marker)
		}
		if !strings.Contains(single, marker) {
			t.Errorf("standalone instruction is missing marker %q (baseline changed?)", marker)
		}
	}
}

func TestWildcardChildInstruction_NoUnsafeSkipDirectives(t *testing.T) {
	child := buildSubdomainScanInstruction("api.example.com", "example.com", "", false)
	for _, forbidden := range []string{
		"SKIP (call finish immediately)",
		"Body size is 0 or very small",
		"Content Hash",
		"Content hash matches",
		"Be efficient. If this subdomain is a duplicate",
		"Redirect goes to the MAIN domain",
	} {
		if strings.Contains(child, forbidden) {
			t.Errorf("wildcard child instruction still contains unsafe skip directive %q", forbidden)
		}
	}
	// The evidence-based classification that replaces them must be present.
	for _, want := range []string{
		"NO SUPERFICIAL SKIPPING",
		"404 homepage can coexist with a functional API",
		"NOT proof of identical security configuration",
		"HTTP and HTTPS both",
	} {
		if !strings.Contains(child, want) {
			t.Errorf("wildcard child instruction missing evidence-based classification marker %q", want)
		}
	}
}

func TestWildcardChildInstruction_CustomInstructionsPropagated(t *testing.T) {
	child := buildSubdomainScanInstruction("api.example.com", "example.com", "FOCUS ONLY ON THE AUTH FLOW", false)
	if !strings.Contains(child, "CUSTOM INSTRUCTIONS") || !strings.Contains(child, "FOCUS ONLY ON THE AUTH FLOW") {
		t.Fatal("operator custom instructions must propagate to wildcard children")
	}
}

func TestComposeWildcardChildInstruction_PropagatesConfiguration(t *testing.T) {
	got := composeWildcardChildInstruction("api.example.com", "example.com", "FOCUS ON AUTH", false,
		true, []int{1, 22}, "passive", "passive")
	for _, marker := range []string{
		"FOCUS ON AUTH",
		"## AUTO-RESUME",
		"PHASE RESTRICTION",
		"MANDATORY ACTIVITY POLICY",
		"NO SUPERFICIAL SKIPPING",
	} {
		if !strings.Contains(got, marker) {
			t.Errorf("composed child instruction missing %q", marker)
		}
	}
	// Fresh (non-resumed) child must not get the resume note.
	got = composeWildcardChildInstruction("api.example.com", "example.com", "", false,
		false, nil, "active", "active")
	if strings.Contains(got, "## AUTO-RESUME") {
		t.Error("fresh child instruction must not carry the AUTO-RESUME note")
	}
	if strings.Contains(got, "PHASE RESTRICTION") {
		t.Error("no phase selection must not emit a phase restriction block")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Resume: parent reporting context reseed
// ─────────────────────────────────────────────────────────────────────────────

func writeScanRecordForTest(t *testing.T, s *Server, target, slug string, rec *ScanRecord) string {
	t.Helper()
	dir := filepath.Join(s.dataDir, target, "2026-01-01", slug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scan.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReseedWildcardParentVulnerabilities(t *testing.T) {
	s := newTestServer(t, nil)
	const instanceID = "inst-reseed-1"

	// Two completed children with durable findings; one pending child with
	// a record on disk that must NOT contribute (it will be resumed itself).
	writeScanRecordForTest(t, s, "api.example.com", "child-aaaa", &ScanRecord{
		ID: "child-aaaa", InstanceID: instanceID, Target: "api.example.com", Status: "finished",
		Vulns: []VulnSummary{{ID: "XALG-1", Title: "SQL Injection in search", Severity: "critical",
			Target: "api.example.com", Endpoint: "/search?q=1"}},
	})
	writeScanRecordForTest(t, s, "admin.example.com", "child-bbbb", &ScanRecord{
		ID: "child-bbbb", InstanceID: instanceID, Target: "admin.example.com", Status: "finished",
		Vulns: []VulnSummary{{ID: "XALG-1", Title: "Reflected XSS in notice banner", Severity: "medium",
			Target: "admin.example.com", Endpoint: "/notice?n=2"}},
	})
	writeScanRecordForTest(t, s, "staging.example.com", "child-cccc", &ScanRecord{
		ID: "child-cccc", InstanceID: instanceID, Target: "staging.example.com", Status: "running",
		Vulns: []VulnSummary{{ID: "XALG-9", Title: "Unfinished host finding", Severity: "low",
			Target: "staging.example.com", Endpoint: "/draft"}},
	})

	parent := &ScanRecord{
		ID: "parent",
		SubScans: []SubScanSummary{
			{ID: "child-aaaa", Target: "api.example.com", Status: "finished"},
			{ID: "child-bbbb", Target: "admin.example.com", Status: "finished"},
			{ID: "child-cccc", Target: "staging.example.com", Status: "running"},
		},
	}

	const parentCtx = "wc-test-reseed-parent-ctx"
	defer reporting.CleanupContext(parentCtx)

	n := s.reseedWildcardParentVulnerabilities(parentCtx, instanceID, parent)
	if n != 2 {
		t.Fatalf("reseeded %d findings, want 2 (running child must be excluded)", n)
	}
	vulns := reporting.GetVulnerabilitiesForContext(parentCtx)
	if len(vulns) != 2 {
		t.Fatalf("parent context holds %d vulns, want 2", len(vulns))
	}
	// Verify the verified evidence itself survived.
	var titles []string
	for _, v := range vulns {
		titles = append(titles, v.Title)
	}
	sort.Strings(titles)
	if titles[0] != "Reflected XSS in notice banner" || titles[1] != "SQL Injection in search" {
		t.Fatalf("restored findings = %v", titles)
	}

	// Idempotent content: reseeding again keeps the same set (IDs renumbered,
	// no semantic duplicates).
	if again := s.reseedWildcardParentVulnerabilities(parentCtx, instanceID, parent); again != 2 {
		t.Fatalf("second reseed added %d, want the same 2 findings (content-stable)", again)
	}
	if len(reporting.GetVulnerabilitiesForContext(parentCtx)) != 2 {
		t.Fatalf("parent context must hold exactly 2 vulns after a repeated reseed")
	}
}

func TestReseedWildcardParentVulnerabilities_NoChildrenIsNoop(t *testing.T) {
	s := newTestServer(t, nil)
	if n := s.reseedWildcardParentVulnerabilities("wc-test-noop-ctx", "inst", &ScanRecord{SubScans: []SubScanSummary{{Target: "a.example.com", Status: "pending"}}}); n != 0 {
		t.Fatalf("no finished children => no reseed, got %d", n)
	}
	if n := s.reseedWildcardParentVulnerabilities("wc-test-noop-ctx", "inst", nil); n != 0 {
		t.Fatalf("nil parent record must be a no-op, got %d", n)
	}
	reporting.CleanupContext("wc-test-noop-ctx")
}

func TestWildcardChildOutcome(t *testing.T) {
	if got := wildcardChildOutcome(nil); got != "failed" {
		t.Fatalf("nil record => %q, want failed", got)
	}
	for _, status := range []string{"finished", "Finished", "stopped", "paused", "running"} {
		if got := wildcardChildOutcome(&ScanRecord{Status: status}); got != "finished" {
			t.Fatalf("status %q => %q, want finished (interrupted states are handled by the stop path)", status, got)
		}
	}
	if got := wildcardChildOutcome(&ScanRecord{Status: "failed"}); got != "failed" {
		t.Fatalf("failed record => %q, want failed", got)
	}
}

// TestWildcardChildInstruction_EquivalentConfigurationToStandalone pins the
// core parity property: with identical operator settings (custom
// instructions, phase selection, recon mode, scan intensity, local-target
// policy), the wildcard child prompt must be EXACTLY the standalone
// single-target prompt, prefixed with the wildcard-child context. Any
// methodology drift between the two modes therefore fails this test.
func TestWildcardChildInstruction_EquivalentConfigurationToStandalone(t *testing.T) {
	custom := "TEST CUSTOM DIRECTIVE"
	phases := []int{1, 6, 22}
	child := composeWildcardChildInstruction("api.example.com", "example.com", custom, true, false, phases, "passive", "active")
	standalone := buildAutonomousInstruction("api.example.com", custom, true) +
		buildPhaseFilterInstruction(phases) +
		buildActivityPolicyInstruction("passive", "active")
	if !strings.HasSuffix(child, standalone) {
		t.Fatal("wildcard child prompt must be the full standalone prompt prefixed with wildcard-child context only")
	}
	if !strings.Contains(child, "WILDCARD CHILD SESSION") {
		t.Fatal("wildcard child prompt must carry the wildcard context prefix")
	}
}

func TestIsMandatoryWildcardEntry(t *testing.T) {
	wt := parseWildcardTarget("www.example.com")
	for _, entry := range []string{"www.example.com", "example.com", "https://www.example.com:8443/app"} {
		if !isMandatoryWildcardEntry(entry, wt) {
			t.Errorf("entry %q must be mandatory for target www.example.com", entry)
		}
	}
	for _, entry := range []string{"api.example.com", "other.com", ""} {
		if isMandatoryWildcardEntry(entry, wt) {
			t.Errorf("entry %q must NOT be mandatory for target www.example.com", entry)
		}
	}
}
