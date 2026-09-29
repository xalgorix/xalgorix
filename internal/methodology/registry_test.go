package methodology

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegistryCanonicalIDs locks the phase IDs and count: every phase 1-22
// exists exactly once and no phantom phases were introduced.
func TestRegistryCanonicalIDs(t *testing.T) {
	if len(Phases) != PhaseCount {
		t.Fatalf("registry has %d phases, want %d", len(Phases), PhaseCount)
	}
	seen := map[int]bool{}
	for i, p := range Phases {
		if p.ID != i+1 {
			t.Fatalf("Phases[%d].ID = %d, want %d (registry must be ordered by ID)", i, p.ID, i+1)
		}
		if seen[p.ID] {
			t.Fatalf("duplicate phase ID %d", p.ID)
		}
		seen[p.ID] = true
		if strings.TrimSpace(p.Name) == "" {
			t.Fatalf("phase %d has an empty name", p.ID)
		}
		if strings.TrimSpace(p.Description) == "" {
			t.Fatalf("phase %d has an empty description", p.ID)
		}
	}
	for id := 1; id <= PhaseCount; id++ {
		if PhaseName(id) == "" {
			t.Fatalf("PhaseName(%d) returned empty for a canonical phase", id)
		}
	}
	if PhaseName(0) != "" || PhaseName(23) != "" {
		t.Fatalf("PhaseName must return empty outside 1-22")
	}
}

// TestAllowsEmptySelectionMeansAllPhases locks the selection semantics: an
// empty selection is the FULL methodology, and a non-empty selection only
// allows its own members.
func TestAllowsEmptySelectionMeansAllPhases(t *testing.T) {
	if !Allows(nil, 1) || !Allows(nil, 22) {
		t.Fatalf("empty selection must allow every phase")
	}
	sel := []int{9, 10, 12}
	if Allows(sel, 9) && Allows(sel, 10) && Allows(sel, 12) {
		// ok
	} else {
		t.Fatalf("selection must allow its own members")
	}
	for _, phase := range []int{1, 5, 6, 7, 8, 11, 14, 16, 17, 20, 22} {
		if Allows(sel, phase) {
			t.Fatalf("Allows(%v, %d) = true, want false", sel, phase)
		}
	}
	if Allows(sel, 0) || Allows(sel, 23) {
		t.Fatalf("Allows must reject non-canonical phase ids")
	}
}

// TestIsReconReportOnlySelection locks the recon-only contract.
func TestIsReconReportOnlySelection(t *testing.T) {
	cases := []struct {
		selection []int
		want      bool
	}{
		{nil, false},
		{[]int{1, 22}, true},
		{[]int{1}, true},
		{[]int{22}, true},
		{[]int{1, 5, 22}, false},
		{[]int{10}, false},
	}
	for _, c := range cases {
		if got := IsReconReportOnlySelection(c.selection); got != c.want {
			t.Fatalf("IsReconReportOnlySelection(%v) = %v, want %v", c.selection, got, c.want)
		}
	}
}

// TestWebuiPhaseListInSync regenerates the webui phase list from the
// canonical registry and compares it with the checked-in
// webui/src/methodology-phases.json the frontend imports. Code sharing
// across languages is impractical, so this schema check is the drift
// guard: anyone editing either side without regenerating the other fails
// this test.
func TestWebuiPhaseListInSync(t *testing.T) {
	type webuiPhase struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	want := make([]webuiPhase, 0, PhaseCount)
	for _, p := range Phases {
		want = append(want, webuiPhase{ID: p.ID, Name: p.Name})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(want); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wantJSON := buf.Bytes()

	// The test runs from internal/methodology; walk up to the repo root.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	path := filepath.Join(root, "webui", "src", "methodology-phases.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(raw) != string(wantJSON) {
		t.Fatalf("webui/src/methodology-phases.json is out of sync with the canonical methodology registry.\nRun: go test ./internal/methodology -run TestWebuiPhaseListInSync after regenerating, or regenerate the file from internal/methodology.Phases.\n--- got ---\n%s\n--- want ---\n%s", string(raw), string(wantJSON))
	}
}
