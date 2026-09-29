package agent

import (
	"strings"
	"testing"
)

// TestProbeArtifactURLsNeverBecomeSurface (P1): the scanner's own probe
// payloads — OAST callbacks, attacker-legend origins like the
// https://evil.com in the CORS methodology example — must never enter the
// endpoint inventory. The pentest-ground production scan burned three
// finish attempts on "content discovery on <oast-host>" and
// "content discovery on evil.com" before exhausting the gate.
func TestProbeArtifactURLsNeverBecomeSurface(t *testing.T) {
	state := NewScanState()
	state.ScanTargets = []string{"https://pentest-ground.com:9000"}

	// Artifact observations are not ingested at all.
	for _, artifact := range []string{
		"https://dau1ipigp7gm33lrnq10hqez6b7kad8dd.oast.live/",
		"https://evil.com/",
		"https://attacker.example.com/",
	} {
		before := len(state.DiscoveredEndpoints)
		RecordSurfaceObservation(state, SurfaceObservation{Endpoint: artifact, Promote: true, Source: "request"})
		if len(state.DiscoveredEndpoints) != before {
			t.Errorf("probe-artifact URL %q entered the discovered inventory", artifact)
		}
		if len(state.ObservedEndpointMethods) > 0 || len(state.EndpointProvenance) > 0 {
			t.Errorf("probe-artifact URL %q polluted the structured surface maps", artifact)
		}
	}

	// A real target observation still lands.
	RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "https://pentest-ground.com:9000/eval?s=1", Promote: true, Source: "request"})
	if len(state.DiscoveredEndpoints) != 1 {
		t.Fatalf("real target endpoint not promoted: %v", state.DiscoveredEndpoints)
	}
}

// TestExtractEndpointFromCmdSkipsProbePayloads (P1): when a payload URL
// (Origin: https://evil.com) appears before the actual target URL in a
// command, the extracted endpoint is the request target — not the legend
// host.
func TestExtractEndpointFromCmdSkipsProbePayloads(t *testing.T) {
	got := extractEndpointFromCmd(`curl -sk -H "Origin: https://evil.com" https://pentest-ground.com:9000/ -D - -o /dev/null`)
	if strings.Contains(got, "evil.com") {
		t.Fatalf("extracted payload host evil.com as the endpoint: %q", got)
	}
	if got != "pentest-ground.com:9000/" {
		t.Fatalf("endpoint = %q, want pentest-ground.com:9000/", got)
	}
}

// TestDistinctApplicationHostsFiltersArtifactsAndOutOfScopeHosts (P1): the
// per-host content-discovery demand only covers in-scope hosts. Probe
// artifacts and external references never become wordlist obligations;
// scope-family subdomains do.
func TestDistinctApplicationHostsFiltersArtifactsAndOutOfScopeHosts(t *testing.T) {
	state := NewScanState()
	state.ScanTargets = []string{"https://pentest-ground.com:9000"}
	state.DiscoveredEndpoints = []string{
		"https://pentest-ground.com:9000/tokens",
		"https://api.pentest-ground.com/health",                 // scope family
		"https://evil.com/",                                     // attacker legend payload
		"https://dau1ipigp7gm33lrnq10hqez6b7kad8dd.oast.live/x", // OAST
		"https://cdn.jsdelivr.net/jquery.js",                    // external reference
	}
	state.DiscoveredHosts = map[string]bool{
		"admin.pentest-ground.com": true, // in-scope family
		"random.oastify.com":       true, // artifact
	}
	hosts := distinctApplicationHosts(state)
	set := map[string]bool{}
	for _, h := range hosts {
		set[h] = true
	}
	if !set["pentest-ground.com:9000"] || !set["api.pentest-ground.com"] || !set["admin.pentest-ground.com"] {
		t.Errorf("in-scope hosts missing from the content-discovery demand: %v", hosts)
	}
	for _, banned := range []string{"evil.com", "dau1ipigp7gm33lrnq10hqez6b7kad8dd.oast.live", "cdn.jsdelivr.net", "random.oastify.com"} {
		for _, h := range hosts {
			if strings.Contains(h, banned) {
				t.Errorf("artifact/external host %q became a content-discovery obligation", h)
			}
		}
	}
}

// TestHostOwesContentDiscoveryIPScopeFallback: with no domain scope (IP or
// unknown targets) the historical behavior is preserved — every
// non-artifact host owes a disposition.
func TestHostOwesContentDiscoveryIPScopeFallback(t *testing.T) {
	state := NewScanState()
	state.ScanTargets = []string{"http://10.10.10.10:8080"}
	if !hostOwesContentDiscovery(state, "10.10.10.10:8080") {
		t.Error("IP target hosts must keep owing content discovery (historical behavior)")
	}
	if hostOwesContentDiscovery(state, "dau1ipigp7gm33lrnq10hqez6b7kad8dd.oast.live") {
		t.Error("artifact hosts never owe content discovery, even without a domain scope")
	}
}

// TestPhaseDispositionEvidenceBeatsNALabel (P2): a phase whose plan tasks
// were all justified-N/A but whose classes carry real engine coverage
// evidence (verify_xxe proved the parser safe; parameter mining ran) reads
// COMPLETED — the pentest-ground scan rendered phase 7 "not applicable"
// while verify_xxe had actually run six times.
func TestPhaseDispositionEvidenceBeatsNALabel(t *testing.T) {
	state := richTestState()
	state.Plan = AutoPlanFromState(state)
	// Phase 7 carries BOTH test-xxe and test-ssrf; settle both lanes.
	// The model probed XXE (engine coverage evidence exists), then the
	// surface turned out not to be exploitable → task skipped N/A. The SSRF
	// lane was never applicable on this surface.
	state.VulnClassesTested["xxe"] = true
	for _, id := range []string{"test-xxe", "test-ssrf"} {
		task := state.Plan.Get(id)
		if task == nil {
			t.Fatalf("expected %s on the fixture surface", id)
		}
		task.Status = TaskSkipped
		task.Disposition = DispositionNotApplicable
		task.Notes = "engine: no XML/URL-fetch surface applies to the observed endpoint set"
	}

	d := ComputePhaseDispositions(state)
	if d[7].Status != PhaseCompleted {
		t.Errorf("phase 7 = %q (%q), want completed: coverage evidence (xxe) outranks the N/A task label", d[7].Status, d[7].Reason)
	}
	if !strings.Contains(d[7].Reason, "xxe") {
		t.Errorf("phase 7 reason should name the exercised classes: %q", d[7].Reason)
	}

	// Same rule for a selected phase that generated NO task but whose class
	// was exercised (e.g. novel-testing on a static target through an
	// LLM-authored plan).
	state2 := NewScanState()
	state2.ScanTargets = []string{"https://app.example.com"}
	state2.AllowedPhases = []int{21, 22}
	state2.DiscoveredEndpoints = []string{"https://app.example.com/", "https://app.example.com/about"}
	state2.Plan = AutoPlanFromState(state2) // static surface: no novel-testing task
	if state2.Plan.Get("test-novel-testing") != nil {
		t.Fatal("fixture must not generate a novel-testing task (static surface)")
	}
	state2.VulnClassesTested["novel-testing"] = true
	d2 := ComputePhaseDispositions(state2)
	if d2[21].Status != PhaseCompleted {
		t.Errorf("phase 21 = %q (%q), want completed from class evidence without a task", d2[21].Status, d2[21].Reason)
	}
}

// TestPhaseDispositionStillNAWithoutEvidence (P2 guard): without evidence
// the honest not_applicable stands — the fix must not turn every skipped
// lane into "completed".
func TestPhaseDispositionStillNAWithoutEvidence(t *testing.T) {
	state := richTestState()
	state.Plan = AutoPlanFromState(state)
	for _, id := range []string{"test-xxe", "test-ssrf", "test-nosqli"} {
		if task := state.Plan.Get(id); task != nil {
			task.Status = TaskSkipped
			task.Disposition = DispositionNotApplicable
			task.Notes = "engine: no applicable surface for this class on the observed target"
		}
	}
	d := ComputePhaseDispositions(state)
	if d[7].Status != PhaseNotApplicable {
		t.Errorf("phase 7 = %q, want not_applicable without any coverage evidence", d[7].Status)
	}
	if d[6].Status == PhaseNotApplicable {
		// sqli/xss tasks are still pending on this fixture → phase 6 pending,
		// never silently N/A.
		t.Errorf("phase 6 = %q — pending lanes must not read not_applicable", d[6].Status)
	}
	if d[6].Status != PhasePending {
		t.Errorf("phase 6 = %q, want pending while sqli/xss tasks are open", d[6].Status)
	}
}
