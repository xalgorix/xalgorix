package reporting

import (
	"strconv"

	"github.com/xalgord/xalgorix/v4/internal/methodology"
)

// MethodologyPhaseNames maps each phase number in the Xalgorix 22-phase
// methodology to its display name. It is DERIVED from the canonical
// internal/methodology registry - the single phase-definition source shared
// by the agent planner, the report generators, and the web layer - so this
// map can never drift from it. It remains exported for existing consumers.
var MethodologyPhaseNames = func() map[int]string {
	m := make(map[int]string, methodology.PhaseCount)
	for _, p := range methodology.Phases {
		m[p.ID] = p.Name
	}
	return m
}()

// MethodologyRow is one rendered methodology-phase row: the phase number,
// canonical name, derived disposition status, and (for non-completed states)
// the auditable reason.
type MethodologyRow struct {
	Num    int
	Name   string
	Status string
	Reason string
}

// Methodology disposition statuses as rendered in reports.
const (
	MethodologyStatusCompleted     = "COMPLETED"
	MethodologyStatusNotApplicable = "NOT APPLICABLE"
	MethodologyStatusBlocked       = "BLOCKED"
	MethodologyStatusNotSelected   = "NOT SELECTED"
	MethodologyStatusSelected      = "SELECTED"
	MethodologyStatusExecuted      = "EXECUTED"
	MethodologyStatusPending       = "PENDING"
)

// MethodologyRows derives the honest per-phase rows for a report:
//
//   - With PhaseStatus (records written since phase dispositions existed):
//     the authoritative derived state — COMPLETED / NOT APPLICABLE / BLOCKED /
//     NOT SELECTED / PENDING — plus the reason.
//   - Legacy records: a phase in PhasesWorked (engine-observed work) renders
//     EXECUTED; a merely selected phase renders SELECTED; unselected phases
//     render NOT SELECTED. Selection alone is never presented as execution.
//
// This is why the table no longer claims "every selected phase was
// executed": scans that skipped, blocked, or proved phases N/A say so.
func MethodologyRows(scan *Scan) []MethodologyRow {
	worked := map[int]bool{}
	for _, p := range scan.PhasesWorked {
		worked[p] = true
	}
	selected := map[int]bool{}
	allSelected := len(scan.Phases) == 0
	for _, p := range scan.Phases {
		selected[p] = true
	}
	rows := make([]MethodologyRow, 0, methodology.PhaseCount)
	for _, def := range methodology.Phases {
		row := MethodologyRow{Num: def.ID, Name: def.Name}
		if st, ok := scan.PhaseStatus[keyFor(def.ID)]; ok {
			row.Status = MethodologyStatusPending
			row.Reason = scan.PhaseReasons[keyFor(def.ID)]
			switch st {
			case "completed":
				row.Status = MethodologyStatusCompleted
			case "not_applicable":
				row.Status = MethodologyStatusNotApplicable
			case "blocked":
				row.Status = MethodologyStatusBlocked
			case "not_selected":
				row.Status = MethodologyStatusNotSelected
			}
			rows = append(rows, row)
			continue
		}
		switch {
		case worked[def.ID]:
			row.Status = MethodologyStatusExecuted
		case allSelected || selected[def.ID]:
			row.Status = MethodologyStatusSelected
		default:
			row.Status = MethodologyStatusNotSelected
		}
		rows = append(rows, row)
	}
	return rows
}

func keyFor(id int) string {
	return strconv.Itoa(id)
}

// OWASPCategories lists the OWASP Top 10 (2021) categories in canonical
// order. The slice is package-level so the report renderer doesn't
// allocate a fresh copy for each generation.
var OWASPCategories = []struct {
	ID   string
	Name string
}{
	{"A01", "Broken Access Control"},
	{"A02", "Cryptographic Failures"},
	{"A03", "Injection"},
	{"A04", "Insecure Design"},
	{"A05", "Security Misconfiguration"},
	{"A06", "Vulnerable and Outdated Components"},
	{"A07", "Identification and Authentication Failures"},
	{"A08", "Software and Data Integrity Failures"},
	{"A09", "Security Logging and Monitoring Failures"},
	{"A10", "Server-Side Request Forgery (SSRF)"},
}
