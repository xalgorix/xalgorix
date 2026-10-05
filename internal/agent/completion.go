// Package agent — completion.go makes the terminal scan status honest.
// The finish gates intentionally release a finish after a bounded rejection
// ceiling (deadlock prevention), which previously meant finish-gate
// exhaustion masqueraded as a fully successful assessment: the "finished"
// event was byte-for-byte identical whether every applicable task was settled
// or the gates simply gave up. The completion assessment now computes an
// explicit terminal state — completed, completed_with_blocked_work, or
// incomplete — with the concrete remaining work listed, so an incomplete
// scan is visibly different and actionable for resume.
//
// It also provides the structured phase/work telemetry (one compact block at
// finish, never flooding the live log): planned classes, tested pairs,
// loaded skills, unresolved hypotheses, recon dimensions, worked phases, and
// the completion status.
package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// Terminal scan completion states.
const (
	CompletionStatusCompleted            = "completed"
	CompletionStatusCompletedWithBlocked = "completed_with_blocked_work"
	CompletionStatusIncomplete           = "incomplete"
)

// defaultMaxFinishRejections mirrors hookFinishGatekeeper's fallback.
const defaultMaxFinishRejections = 15

// scanCompletionAssessment computes the honest terminal state for a scan
// (root coordinator scope unless the state is a delegated specialist, whose
// owner-scoped ledger work is assessed).
//
//	status = completed                — all applicable work settled
//	status = completed_with_blocked_work — settled except explicitly blocked work
//	status = incomplete               — applicable work remains (never "success"
//	                                     merely because the gates gave up)
//
// The returned reasons name every piece of remaining work so an incomplete
// finish is directly actionable for resume.
func scanCompletionAssessment(state *ScanState) (string, []string) {
	if state == nil {
		return CompletionStatusCompleted, nil
	}
	var reasons []string

	// Plan: pending/active tasks are unfinished work. (Phase 20/22 are no
	// longer plan tasks — verification and reporting are derived states.)
	if state.Plan != nil {
		for _, t := range state.Plan.Tasks {
			if t.Status == TaskPending || t.Status == TaskActive {
				reasons = append(reasons, fmt.Sprintf("plan task %q (phase %d) %s", t.ID, t.Phase, t.Status))
			}
		}
	}

	// Ledger: claimed-but-unclosed and proven-but-unreported hypotheses.
	owner := ""
	if state.DelegatedAgent {
		owner = state.DelegatedAgentID
	}
	if l := ledgerForState(state); l != nil {
		if testing := testingHypothesesForOwner(l, owner); len(testing) > 0 {
			reasons = append(reasons, "hypotheses claimed but not closed: "+strings.Join(testing, ", "))
		}
		if unreported := provenUnreportedHypothesesForOwner(l, owner, state.ScanContextID); len(unreported) > 0 {
			reasons = append(reasons, "hypotheses proven but unreported: "+strings.Join(unreported, ", "))
		}
	}

	// Gate exhaustion: the finish went through because the retry ceiling
	// released it, not because the contract was met.
	maxRej := state.MaxFinishRejections
	if maxRej <= 0 {
		maxRej = defaultMaxFinishRejections
	}
	if state.FinishAttempts > maxRej {
		reasons = append(reasons, "finish_gate_exhausted: gates released the finish after the bounded rejection ceiling")
	}

	if len(reasons) == 0 {
		if scanHasBlockedWork(state, owner) {
			return CompletionStatusCompletedWithBlocked, nil
		}
		return CompletionStatusCompleted, nil
	}
	return CompletionStatusIncomplete, reasons
}

// scanHasBlockedWork reports explicitly blocked-but-honest work: plan tasks
// dispositioned blocked_* and ledger hypotheses in the blocked state. Blocked
// work is visible and resumable, but it is not silently folded into a
// "completed" status.
func scanHasBlockedWork(state *ScanState, owner string) bool {
	if state == nil {
		return false
	}
	if state.Plan != nil {
		for _, t := range state.Plan.Tasks {
			if t.Status == TaskSkipped && strings.HasPrefix(t.Disposition, "blocked_") {
				return true
			}
		}
	}
	if l := ledgerForState(state); l != nil {
		for _, h := range l.All() {
			if h.Status == scanctx.HypothesisBlocked && hypothesisBelongsToOwner(h, owner) {
				return true
			}
		}
	}
	return false
}

// formatIncompleteSummary renders the honest incomplete banner for the final
// event content. It never reads as "full assessment completed".
func formatIncompleteSummary(status string, reasons []string) string {
	var b strings.Builder
	b.WriteString("⚠️ ASSESSMENT " + strings.ToUpper(status))
	if status == CompletionStatusIncomplete {
		b.WriteString(" — the applicable surface was NOT fully tested. Remaining work:")
		for _, r := range reasons {
			b.WriteString("\n  • " + r)
		}
		b.WriteString("\nThe scan remains resumable: the hypothesis ledger and this remaining-work list are preserved.")
	} else {
		b.WriteString(" — all applicable work is settled; blocked work is recorded with its typed reason and remains resumable.")
	}
	return b.String()
}

// scanTelemetrySummary produces the compact structured telemetry block emitted
// once at finish (Part 19). It answers "why did the scan (not) do X" without
// reading the transcript: planned/applicable classes, tested pairs, loaded
// skills, specialist lanes, unresolved hypotheses, recon dimensions, worked
// phases, and the completion status.
func scanTelemetrySummary(state *ScanState, status string, reasons []string) string {
	if state == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("📊 SCAN TELEMETRY\n")

	// Planned and tested classes.
	if state.Plan != nil {
		planned := make([]string, 0, len(state.Plan.Tasks))
		for _, t := range state.Plan.Tasks {
			if t.VulnClass != "" {
				planned = append(planned, t.VulnClass)
			}
		}
		sort.Strings(planned)
		fmt.Fprintf(&b, "planned classes: %s\n", strings.Join(dedupeStrings(planned), ", "))
	}
	tested := make([]string, 0, len(state.VulnClassesTested))
	for class := range state.VulnClassesTested {
		tested = append(tested, class)
	}
	sort.Strings(tested)
	fmt.Fprintf(&b, "classes with coverage evidence: %s\n", strings.Join(tested, ", "))

	// Endpoint × class pairs.
	pairs := 0
	for _, classes := range state.EndpointClassCoverage {
		pairs += len(classes)
	}
	fmt.Fprintf(&b, "tested endpoint×class pairs: %d (endpoints discovered: %d, tested: %d)\n",
		pairs, len(state.DiscoveredEndpoints), len(state.EndpointsTested))

	// Skills.
	if names := LoadedSkillNames(state); len(names) > 0 {
		fmt.Fprintf(&b, "loaded skills: %s (failed lookups: %d)\n", strings.Join(names, ", "), state.FailedSkillLoads)
	} else {
		fmt.Fprintf(&b, "loaded skills: none (failed lookups: %d)\n", state.FailedSkillLoads)
	}

	// Specialist lanes.
	lanes := "none"
	var launched []string
	if state.ReconLaneLaunched {
		launched = append(launched, "recon-discovery")
	}
	if state.WaveLaunched {
		launched = append(launched, "testing-wave")
	}
	if len(launched) > 0 {
		lanes = strings.Join(launched, "+")
	}
	fmt.Fprintf(&b, "specialist lanes: %s (delegation attempted: %v, deferred: %s)\n",
		lanes, state.DelegationAttempted, orDefault(state.DelegationDeferReason, "-"))

	// Ledger state.
	if l := ledgerForState(state); l != nil {
		counts := map[scanctx.HypothesisStatus]int{}
		for _, h := range l.All() {
			counts[h.Status]++
		}
		fmt.Fprintf(&b, "ledger: %d queued, %d testing, %d proven, %d rejected, %d blocked, %d exhausted\n",
			counts[scanctx.HypothesisQueued], counts[scanctx.HypothesisTesting],
			counts[scanctx.HypothesisProven], counts[scanctx.HypothesisRejected],
			counts[scanctx.HypothesisBlocked], counts[scanctx.HypothesisExhausted])
	}

	// Recon dimensions.
	rc := state.ReconCoverage
	fmt.Fprintf(&b, "recon: dns=%v services=%v http=%v tech=%v crawled=%v js=%v api=%v params=%v auth=%s contentHosts=%d naDims=%d\n",
		rc.DNSResolved, rc.ServicesProbed, rc.HTTPProbed, rc.TechFingerprinted,
		rc.Crawled, rc.JSAnalyzed, rc.APISurfaceDiscovered, rc.ParamDiscovered,
		orDefault(rc.AuthMapped, "pending"), len(rc.ContentDiscoveredHosts), len(rc.NAMarked))

	// Worked phases.
	if phases := planWorkedPhasesFor(state); len(phases) > 0 {
		fmt.Fprintf(&b, "worked phases: %v\n", phases)
	}

	// Phase dispositions (derived, authoritative per-phase state).
	if block := FormatPhaseDispositions(ComputePhaseDispositions(state)); block != "" {
		fmt.Fprintf(&b, "%s\n", block)
	}

	// Completion.
	fmt.Fprintf(&b, "completion status: %s\n", status)
	if len(reasons) > 0 {
		fmt.Fprintf(&b, "completion reasons: %s\n", strings.Join(reasons, "; "))
	}
	return strings.TrimRight(b.String(), "\n")
}

// planWorkedPhasesFor returns the methodology phases of COMPLETED plan tasks —
// worked phases have executable evidence, dispositions do not count.
func planWorkedPhasesFor(state *ScanState) []int {
	if state == nil || state.Plan == nil {
		return nil
	}
	seen := map[int]bool{}
	var phases []int
	for _, t := range state.Plan.Tasks {
		if t.Status == TaskCompleted && t.Phase > 0 && !seen[t.Phase] {
			seen[t.Phase] = true
			phases = append(phases, t.Phase)
		}
	}
	sort.Ints(phases)
	return phases
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
