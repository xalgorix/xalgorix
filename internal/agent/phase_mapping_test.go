package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/methodology"
)

// TestCanonicalClassPhaseMapping is the table-driven lock over EVERY
// canonical vulnerability class: its methodology phase must match the
// advertised 22-phase methodology. No registered class may silently fall
// back to Phase 6, and unknown classes must return 0 — never "injection".
func TestCanonicalClassPhaseMapping(t *testing.T) {
	want := map[string]int{
		// Phase 2 — manual/exposure discovery
		"parameter_mining":     2,
		"file_disclosure":      2,
		"information-exposure": 2,
		"secret-exposure":      2,
		// Phase 3
		"dirbusting": 3,
		// Phase 4 — REAL CORS & cookie analysis (parameter mining is NOT a
		// phase-4 substitute)
		"cors":            4,
		"cookie-security": 4,
		// Phase 5 — authentication & session (incl. auth-centric bypass)
		"auth":        5,
		"csrf":        5,
		"api-auth":    5,
		"auth-bypass": 5,
		// Phase 6 — injection
		"sqli":                6,
		"nosqli":              6,
		"xss":                 6,
		"dom-xss":             6,
		"ssti":                6,
		"cmdi":                6,
		"path_traversal":      6,
		"crlf":                6,
		"prototype-pollution": 6,
		// Phase 7
		"ssrf": 7,
		"xxe":  7,
		// Phase 8 — broken access control
		"idor":                 8,
		"privilege-escalation": 8,
		"mass-assignment":      8,
		// Phase 9 — API & GraphQL
		"graphql": 9,
		// Phase 10
		"file-upload": 10,
		// Phase 11 — deserialization & RCE
		"deserialization": 11,
		"rce":             11,
		// Phase 12 — race & business logic
		"business-logic":  12,
		"race-conditions": 12,
		// Phase 13
		"subdomain-takeover": 13,
		// Phase 14
		"open-redirect": 14,
		// Phase 15
		"email-security": 15,
		// Phase 16
		"cloud-config":  16,
		"cloud-storage": 16,
		// Phase 17
		"websocket": 17,
		// Phase 18
		"cms-security": 18,
		// Phase 19
		"broken-link-hijacking": 19,
		"content-spoofing":      19,
		// Phase 21 — bounded novel discovery
		"novel-testing": 21,
	}
	for _, def := range vulnClassRegistry {
		wantPhase, ok := want[def.ID]
		if !ok {
			t.Errorf("class %q has no expected-phase entry in the mapping table — add it to the test", def.ID)
			continue
		}
		if def.Phase != wantPhase {
			t.Errorf("class %q: registry phase = %d, want %d", def.ID, def.Phase, wantPhase)
		}
		if got := classPhase(def.ID); got != wantPhase {
			t.Errorf("classPhase(%q) = %d, want %d", def.ID, got, wantPhase)
		}
		// Every alias resolves to the same phase.
		for _, alias := range def.Aliases {
			if got := classPhase(alias); got != wantPhase {
				t.Errorf("classPhase(alias %q of %q) = %d, want %d", alias, def.ID, got, wantPhase)
			}
		}
		if !methodology.ValidPhase(def.Phase) {
			t.Errorf("class %q carries non-canonical phase %d", def.ID, def.Phase)
		}
	}
}

// TestClassPhaseUnknownIsNeverInjection: the historical classPhase switch
// defaulted every unknown class to Phase 6 (injection). That silent
// misclassification must never return.
func TestClassPhaseUnknownIsNeverInjection(t *testing.T) {
	for _, unknown := range []string{"", "totally-unknown-class", "madeup", "newly invented class"} {
		if got := classPhase(unknown); got != 0 {
			t.Errorf("classPhase(%q) = %d, want 0 for unknown classes (never a silent Phase 6)", unknown, got)
		}
	}
}

// TestClassAllowedForSelection locks the phase-scope filter for classes.
func TestClassAllowedForSelection(t *testing.T) {
	if !classAllowedForSelection(nil, "sqli") || !classAllowedForSelection([]int{}, "sqli") {
		t.Fatal("empty selection (full methodology) must allow every class")
	}
	sel := []int{9, 10, 12}
	for _, allowed := range []string{"graphql", "file-upload", "business-logic", "race-conditions"} {
		if !classAllowedForSelection(sel, allowed) {
			t.Errorf("classAllowedForSelection(%v, %q) = false, want true", sel, allowed)
		}
	}
	for _, excluded := range []string{"sqli", "xss", "ssrf", "xxe", "auth", "idor", "open-redirect", "deserialization", "websocket", "cors"} {
		if classAllowedForSelection(sel, excluded) {
			t.Errorf("classAllowedForSelection(%v, %q) = true, want false", sel, excluded)
		}
	}
	// Unknown classes are conservatively excluded under a restriction.
	if classAllowedForSelection(sel, "madeup-class") {
		t.Error("unknown class must be excluded under a phase restriction")
	}
}

// TestSelectionNeedsRouteDiscovery locks the prerequisite-profile routing:
// pure domain-level phases do not owe web route discovery, everything else
// does.
func TestSelectionNeedsRouteDiscovery(t *testing.T) {
	if selectionNeedsRouteDiscovery([]int{13}) || selectionNeedsRouteDiscovery([]int{15, 16}) {
		t.Error("pure domain-level phases (13/15/16) must not demand web route discovery")
	}
	if selectionNeedsRouteDiscovery([]int{22}) {
		t.Error("a report-only selection must not demand route discovery")
	}
	// [1,22] DOES owe content discovery: it is part of the selected Phase 1
	// comprehensive-recon contract.
	if !selectionNeedsRouteDiscovery([]int{1, 22}) {
		t.Error("recon-selected scans owe (bounded) content discovery as part of the recon contract")
	}
	for _, sel := range [][]int{{10}, {9}, {12}, {17}, {21}, {6}, {8}} {
		if !selectionNeedsRouteDiscovery(sel) {
			t.Errorf("selectionNeedsRouteDiscovery(%v) = false, want true", sel)
		}
	}
}

// TestPrerequisiteProfileNotes: restricted selections receive a bounded,
// per-phase prerequisite contract that names what to DISCOVER — and what to
// skip (excluded methodology).
func TestPrerequisiteProfileNotes(t *testing.T) {
	notes := prerequisiteProfileNotes([]int{10})
	for _, want := range []string{
		"TECHNICAL PREREQUISITE",
		"upload route discovery",
		"do NOT run methodology of excluded phases",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("phase-10 prerequisite notes missing %q:\n%s", want, notes)
		}
	}
	// Phase 12 gets application modeling; phase 17 gets WebSocket discovery.
	if notes12 := prerequisiteProfileNotes([]int{12}); !strings.Contains(notes12, "application modeling") {
		t.Errorf("phase-12 prerequisite notes missing workflow modeling:\n%s", notes12)
	}
	if notes17 := prerequisiteProfileNotes([]int{17}); !strings.Contains(notes17, "WebSocket URL discovery") {
		t.Errorf("phase-17 prerequisite notes missing websocket discovery:\n%s", notes17)
	}
}
