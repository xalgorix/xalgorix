package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/reporting"
)

// TestReportingPipelineCopiesPhaseEvidence: the report conversion carries
// the phase dispositions and the worked ledger into reporting.Scan — the
// honest methodology section depends on them surviving the transport.
func TestReportingPipelineCopiesPhaseEvidence(t *testing.T) {
	rec := &ScanRecord{
		Phases:       []int{1, 6},
		PhasesWorked: []int{1, 6},
		PhaseStatus: map[string]string{
			"1": "completed",
			"6": "completed",
			"9": "not_applicable",
		},
		PhaseReasons: map[string]string{"9": "no structured API/GraphQL surface identified"},
	}
	conv := toReportingScan(rec)
	if len(conv.PhasesWorked) != 2 {
		t.Fatalf("conversion dropped PhasesWorked: %+v", conv.PhasesWorked)
	}
	if conv.PhaseStatus["6"] != "completed" {
		t.Fatalf("conversion dropped PhaseStatus: %+v", conv.PhaseStatus)
	}
	if conv.PhaseReasons["9"] == "" {
		t.Fatal("conversion dropped PhaseReasons")
	}
	// The derived rows flow through the shared builder.
	rows := reporting.MethodologyRows(conv)
	byPhase := map[int]reporting.MethodologyRow{}
	for _, r := range rows {
		byPhase[r.Num] = r
	}
	if byPhase[1].Status != reporting.MethodologyStatusCompleted || byPhase[6].Status != reporting.MethodologyStatusCompleted {
		t.Errorf("phases 1/6 rows = %q/%q, want COMPLETED from the derived dispositions", byPhase[1].Status, byPhase[6].Status)
	}
	if byPhase[9].Status != reporting.MethodologyStatusNotApplicable {
		t.Errorf("phase 9 row = %q, want NOT APPLICABLE from the derived reason", byPhase[9].Status)
	}
}

// TestScanRecordPhaseStatusJSON: the persisted/API record exposes
// phase_status and phase_reasons under their stable JSON keys — the
// webui phase-progress contract.
func TestScanRecordPhaseStatusJSON(t *testing.T) {
	rec := ScanRecord{
		ID:           "json-check",
		PhaseStatus:  map[string]string{"12": "completed"},
		PhaseReasons: map[string]string{"17": "no WebSocket surface identified"},
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	blob := string(raw)
	for _, key := range []string{`"phase_status"`, `"phase_reasons"`} {
		if !strings.Contains(blob, key) {
			t.Errorf("ScanRecord JSON missing %s: %s", key, blob)
		}
	}
}
