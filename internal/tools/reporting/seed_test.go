package reporting

import "testing"

func TestSeedVulnsForContext_DedupesAndRenumbers(t *testing.T) {
	const ctx = "seed-test-ctx"
	defer CleanupContext(ctx)

	base := []Vulnerability{
		{ID: "XALG-1", Title: "SQL Injection in search", Description: "d1", Target: "a.example.com", Endpoint: "/search"},
		{ID: "XALG-2", Title: "Reflected XSS in banner", Description: "d2", Target: "a.example.com", Endpoint: "/banner"},
	}
	if n := SeedVulnsForContext(ctx, base); n != 2 {
		t.Fatalf("first seed added %d, want 2", n)
	}
	// Re-seeding the same findings (e.g. re-running the reseed after another
	// interruption) must not duplicate anything.
	if n := SeedVulnsForContext(ctx, base); n != 0 {
		t.Fatalf("re-seed added %d, want 0 (semantic dedup)", n)
	}
	// A genuinely new finding whose persisted ID collides gets renumbered.
	if n := SeedVulnsForContext(ctx, []Vulnerability{
		{ID: "XALG-1", Title: "Command injection in status", Description: "d3", Target: "b.example.com", Endpoint: "/status"},
	}); n != 1 {
		t.Fatalf("colliding-ID seed added %d, want 1", n)
	}
	got := GetVulnerabilitiesForContext(ctx)
	if len(got) != 3 {
		t.Fatalf("context holds %d vulns, want 3", len(got))
	}
	ids := map[string]bool{}
	for _, v := range got {
		if ids[v.ID] {
			t.Fatalf("duplicate ID after renumbering: %s", v.ID)
		}
		ids[v.ID] = true
	}
}

func TestSeedVulnsForContext_EmptyInputs(t *testing.T) {
	if n := SeedVulnsForContext("", []Vulnerability{{ID: "XALG-1"}}); n != 0 {
		t.Fatalf("empty context id must be a no-op, got %d", n)
	}
	if n := SeedVulnsForContext("seed-test-ctx-2", nil); n != 0 {
		t.Fatalf("empty vuln list must be a no-op, got %d", n)
	}
	CleanupContext("seed-test-ctx-2")
}
