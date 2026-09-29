// Package agent — phase_disposition.go is the authoritative per-phase
// runtime state model. Phase status is DERIVED from engine evidence —
// completed plan tasks, typed task dispositions, hypothesis-ledger state,
// and the terminal lifecycle — never from LLM prose or from "the current
// phase number is past N" (CurrentPhase is UI narration only; parsePhaseMention
// in the web layer stays a live-narration signal and is never authoritative).
//
// Consumers: the web scan record (`phase_status`), the phase-progress UI, and
// the honest methodology section of the PDF report. The finish contract
// already blocks while plan tasks are pending/active; these dispositions make
// the terminal picture explicit and per-phase.
package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// PhaseStatus is the runtime disposition of one methodology phase.
type PhaseStatus string

const (
	PhasePending       PhaseStatus = "pending"        // selected, not yet started
	PhaseActive        PhaseStatus = "active"         // work in progress
	PhaseCompleted     PhaseStatus = "completed"      // executed (or settled) with engine evidence
	PhaseBlocked       PhaseStatus = "blocked"        // attempted and stuck on a legitimate prerequisite
	PhaseNotApplicable PhaseStatus = "not_applicable" // surface evidence proves the phase does not apply
	PhaseNotSelected   PhaseStatus = "not_selected"   // excluded by the operator's phase selection
)

// PhaseDisposition is the derived terminal-or-live state of one phase. It
// deliberately does not duplicate task truth: TaskIDs names the plan tasks
// the status was derived from, and the authoritative per-task state stays in
// the plan.
type PhaseDisposition struct {
	Phase   int         `json:"phase"`
	Status  PhaseStatus `json:"status"`
	TaskIDs []string    `json:"task_ids,omitempty"`
	Reason  string      `json:"reason,omitempty"`
}

// ComputePhaseDispositions derives the disposition of every phase 1-22 from
// the scan state. Deterministic and read-only.
func ComputePhaseDispositions(state *ScanState) map[int]PhaseDisposition {
	out := make(map[int]PhaseDisposition, 22)
	if state == nil {
		return out
	}
	surfaceKnown := len(state.DiscoveredEndpoints) > 0 ||
		len(state.SeededSurface) > 0 || state.ReconDone
	for phase := 1; phase <= 22; phase++ {
		out[phase] = dispositionForPhase(state, phase, surfaceKnown)
	}
	return out
}

// dispositionForPhase derives one phase's state.
func dispositionForPhase(state *ScanState, phase int, surfaceKnown bool) PhaseDisposition {
	d := PhaseDisposition{Phase: phase}
	if !phaseAllowedForState(state, phase) {
		d.Status = PhaseNotSelected
		d.Reason = "excluded by operator phase selection"
		return d
	}
	switch phase {
	case 20:
		return verificationDisposition(state)
	case 22:
		return reportDisposition(state)
	}
	// Task-derived phases: a methodology task that is not a technical
	// prerequisite is the phase's real work.
	var tasks []*Task
	if state.Plan != nil {
		for _, t := range state.Plan.Tasks {
			if t.Phase == phase && !t.Prerequisite {
				tasks = append(tasks, t)
			}
		}
	}
	if len(tasks) == 0 {
		// Selected but no obligation was generated. Before the surface is
		// mapped this is pending (never a premature N/A); afterwards the
		// absence of an obligation IS the not-applicable evidence.
		if !surfaceKnown {
			d.Status = PhasePending
			d.Reason = "surface not yet mapped"
			return d
		}
		d.Status = PhaseNotApplicable
		d.Reason = phaseNotApplicableReason(state, phase)
		return d
	}
	for _, t := range tasks {
		d.TaskIDs = append(d.TaskIDs, t.ID)
	}
	sort.Strings(d.TaskIDs)

	var pending, active, completed, na, blocked int
	var blockedReason string
	for _, t := range tasks {
		switch {
		case t.Status == TaskPending:
			pending++
		case t.Status == TaskActive:
			active++
		case t.Status == TaskCompleted:
			completed++
		case t.Status == TaskSkipped && strings.HasPrefix(t.Disposition, "blocked_"):
			blocked++
			if blockedReason == "" {
				blockedReason = t.ID + ": " + orDefault(t.Disposition, "blocked")
			}
		case t.Status == TaskSkipped:
			na++
		}
	}
	switch {
	case active > 0:
		d.Status = PhaseActive
	case pending > 0:
		d.Status = PhasePending
		d.Reason = "plan tasks pending"
	case blocked > 0:
		d.Status = PhaseBlocked
		d.Reason = blockedReason
	case completed > 0:
		d.Status = PhaseCompleted
	default:
		// Only justified N/A dispositions remain.
		d.Status = PhaseNotApplicable
		d.Reason = phaseNotApplicableReason(state, phase)
	}
	return d
}

// verificationDisposition derives Phase 20 (Exploit Verification) from the
// hypothesis ledger: the cross-cutting phase is settled when every
// actionable candidate holds a verified (proven+reported), rejected, or
// blocked/unverifiable disposition. It never demands re-testing negative
// classes at the end.
func verificationDisposition(state *ScanState) PhaseDisposition {
	d := PhaseDisposition{Phase: 20}
	l := ledgerForState(state)
	if l == nil {
		d.Status = PhasePending
		d.Reason = "hypothesis ledger unavailable"
		return d
	}
	counts := map[scanctx.HypothesisStatus]int{}
	for _, h := range l.All() {
		counts[h.Status]++
	}
	switch {
	case counts[scanctx.HypothesisTesting] > 0:
		d.Status = PhaseActive
		d.Reason = "hypotheses under verification"
	case counts[scanctx.HypothesisQueued] > 0:
		d.Status = PhasePending
		d.Reason = "queued candidates await verification"
	case l.Len() == 0:
		d.Status = PhaseNotApplicable
		d.Reason = "no actionable candidates were raised"
	default:
		d.Status = PhaseCompleted
		d.Reason = fmt.Sprintf("all candidates dispositioned (%d proven, %d rejected, %d blocked, %d exhausted)",
			counts[scanctx.HypothesisProven], counts[scanctx.HypothesisRejected],
			counts[scanctx.HypothesisBlocked], counts[scanctx.HypothesisExhausted])
	}
	return d
}

// reportDisposition derives Phase 22 (Final Report) from the terminal
// lifecycle: pending while the scan runs, completed when a finish was
// accepted (including completed_with_blocked_work), blocked when the scan
// terminated incomplete (abnormal abort, finish-gate exhaustion).
func reportDisposition(state *ScanState) PhaseDisposition {
	d := PhaseDisposition{Phase: 22}
	switch state.CompletionStatus {
	case CompletionStatusCompleted, CompletionStatusCompletedWithBlocked:
		d.Status = PhaseCompleted
		d.Reason = "finish accepted; report generated from the settled assessment"
	case CompletionStatusIncomplete:
		d.Status = PhaseBlocked
		d.Reason = "assessment terminated incomplete — remaining work preserved for resume"
	default:
		d.Status = PhasePending
		d.Reason = "scan still running"
	}
	return d
}

// phaseNotApplicableReason names the absent surface element for a selected
// phase that generated no obligation — the auditable justification the
// report and UI surface.
func phaseNotApplicableReason(state *ScanState, phase int) string {
	switch phase {
	case 2:
		return "no anomaly/exposure obligations on the observed surface"
	case 4:
		if !cookieSurfaceObserved(state) && !webSurfaceObserved(state) {
			return "no web surface identified"
		}
		return "no cookie-authenticated/browser cross-origin surface identified"
	case 5:
		return "no authentication/session surface identified"
	case 9:
		return "no structured API/GraphQL surface identified"
	case 10:
		return "no file-upload/processing surface identified"
	case 11:
		return "no deserialization/RCE surface identified"
	case 13:
		return "scan scope is an explicit host — no subdomain takeover surface"
	case 15:
		return "no mail infrastructure in engagement scope"
	case 16:
		return "no cloud/infrastructure surface identified"
	case 17:
		return "no WebSocket surface identified"
	case 18:
		return "no CMS fingerprinted"
	case 19:
		return "no trusted external references observed on in-scope pages"
	case 21:
		return "static/simple target — bounded novel discovery does not apply"
	}
	return "no applicable surface for this phase"
}

// PhaseDispositions returns the derived per-phase dispositions for the
// agent's scan (web/telemetry entry point).
func (a *Agent) PhaseDispositions() map[int]PhaseDisposition {
	if a == nil || a.state == nil {
		return nil
	}
	return ComputePhaseDispositions(a.state)
}

// PhaseStatusMap renders the dispositions as the compact web-facing map
// keyed by decimal phase id ("1".."22") — the JSON shape consumed by the
// scan record and the phase-progress UI.
func PhaseStatusMap(dispositions map[int]PhaseDisposition) map[string]string {
	if len(dispositions) == 0 {
		return nil
	}
	out := make(map[string]string, len(dispositions))
	for phase, d := range dispositions {
		out[fmt.Sprintf("%d", phase)] = string(d.Status)
	}
	return out
}

// PhaseReasonMap renders the auditable per-phase reasons as the compact
// web-facing map keyed by decimal phase id.
func PhaseReasonMap(dispositions map[int]PhaseDisposition) map[string]string {
	out := make(map[string]string, len(dispositions))
	for phase, d := range dispositions {
		if d.Reason != "" {
			out[fmt.Sprintf("%d", phase)] = d.Reason
		}
	}
	return out
}

// FormatPhaseDispositions renders the dispositions as a compact
// model/operator-facing summary block (telemetry).
func FormatPhaseDispositions(dispositions map[int]PhaseDisposition) string {
	if len(dispositions) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("phase dispositions:")
	for phase := 1; phase <= 22; phase++ {
		d, ok := dispositions[phase]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "\n  %2d %s", phase, d.Status)
		if d.Reason != "" {
			fmt.Fprintf(&b, " — %s", d.Reason)
		}
	}
	return b.String()
}
