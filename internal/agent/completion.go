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
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// Terminal scan completion states.
const (
	CompletionStatusCompleted            = "completed"
	CompletionStatusCompletedWithBlocked = "completed_with_blocked_work"
	CompletionStatusIncomplete           = "incomplete"
)

// Typed stop reasons an incomplete assessment carries to the scan record.
const (
	StopReasonFinishGateExhausted = "finish_gate_exhausted"
	StopReasonUntestedAtFinish    = "untested_at_finish"
)

// completionStopReason maps incomplete-assessment reasons to the typed stop
// reason recorded on the scan ("" when none applies). Gate exhaustion wins.
func completionStopReason(reasons []string) string {
	for _, prefix := range []string{StopReasonFinishGateExhausted, StopReasonUntestedAtFinish} {
		for _, r := range reasons {
			if strings.HasPrefix(r, prefix+":") {
				return prefix
			}
		}
	}
	return ""
}

// validatedFindingCount is the number of reported findings for the scan.
func validatedFindingCount(state *ScanState) int {
	if state == nil || state.ScanContextID == "" {
		return 0
	}
	return len(reporting.GetVulnerabilitiesForContext(state.ScanContextID))
}

// settleCompletion computes the terminal assessment and records it on the
// state (status and typed stop reason). Both finish paths use it.
func settleCompletion(state *ScanState) (string, []string) {
	status, reasons := scanCompletionAssessment(state)
	if state != nil {
		state.CompletionStatus = status
		state.CompletionStopReason = ""
		if status == CompletionStatusIncomplete {
			state.CompletionStopReason = completionStopReason(reasons)
		}
	}
	return status, reasons
}

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
		reasons = append(reasons, StopReasonFinishGateExhausted+": the scan reached its finish limit before every check was confirmed")
	}

	// Principled finish that closed plan work WITHOUT executing it and has no
	// validated finding: a zero-finding report must not read as full coverage
	// of a plan that was mostly never run.
	if !state.DelegatedAgent {
		if untested := untestedAtFinishCount(state); untested > 0 && validatedFindingCount(state) == 0 {
			reasons = append(reasons, fmt.Sprintf("%s: %s closed at the finish without running", StopReasonUntestedAtFinish, plannedChecks(untested)))
		}
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

// formatIncompleteSummary renders the coverage note appended to the final
// event content, which hosted dashboards show to customers in the scan log.
// It is written for the person who ordered the scan: plain words, no alarm
// styling, no engine internals. It still never reads as full coverage when
// work remains, because a clean result over untested areas is not a clean bill
// of health. The typed reasons are unchanged (completionStopReason and the
// telemetry read them); only their display is reworded here.
func formatIncompleteSummary(status string, reasons []string) string {
	var b strings.Builder
	if status == CompletionStatusIncomplete {
		b.WriteString("Coverage note: the scan finished before every planned check ran, so areas that weren't tested may still have issues. Remaining:")
		for _, r := range reasons {
			b.WriteString("\n  • " + customerReason(r))
		}
		b.WriteString("\nResume or re-run the scan to cover them.")
		return b.String()
	}
	b.WriteString("Coverage note: everything that could be tested was tested. Some checks were blocked and could not run; each is recorded with its reason and can be resumed.")
	return b.String()
}

// customerReasonPrefixes rewords the start of each typed remaining-work reason
// for display. Typed stop-reason prefixes are dropped; their text is already
// plain language.
var customerReasonPrefixes = []struct{ from, to string }{
	{StopReasonUntestedAtFinish + ": ", ""},
	{StopReasonFinishGateExhausted + ": ", ""},
	{"hypotheses claimed but not closed: ", "leads still open: "},
	{"hypotheses proven but unreported: ", "confirmed leads not yet reported: "},
	{"plan task ", "planned check "},
}

func customerReason(reason string) string {
	for _, p := range customerReasonPrefixes {
		if strings.HasPrefix(reason, p.from) {
			return p.to + strings.TrimPrefix(reason, p.from)
		}
	}
	return reason
}

// plannedChecksNoun renders "1 planned check" / "N planned checks".
func plannedChecksNoun(n int) string {
	if n == 1 {
		return "1 planned check"
	}
	return fmt.Sprintf("%d planned checks", n)
}

// plannedChecks renders "1 planned check was" / "N planned checks were".
func plannedChecks(n int) string {
	if n == 1 {
		return plannedChecksNoun(n) + " was"
	}
	return plannedChecksNoun(n) + " were"
}

// saturatedCoverageSentence says, in plain words, what a saturated finish left
// untested. It returns "" when nothing was left, otherwise a sentence that
// starts with a space so callers can append it.
func saturatedCoverageSentence(untested, touched, applicable int) string {
	routes := "routes that accept input"
	if applicable == 1 {
		routes = "route that accepts input"
	}
	switch {
	case untested > 0 && applicable > 0:
		return fmt.Sprintf(" %s did not run, and injection testing reached %d of %d %s.", plannedChecksNoun(untested), touched, applicable, routes)
	case untested > 0:
		return fmt.Sprintf(" %s did not run.", plannedChecksNoun(untested))
	case applicable > 0:
		return fmt.Sprintf(" Injection testing reached %d of %d %s.", touched, applicable, routes)
	}
	return ""
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

	// Principled-finish residual: when the scan closed plan tasks without
	// executing them, say how many and record the (route,class) pairs that were
	// NOT tested, so the tradeoff is transparent rather than silent.
	if untested := untestedAtFinishCount(state); untested > 0 {
		touched, applicable := routeTouchCounts(state)
		fmt.Fprintf(&b, "principled finish: %d plan task(s) closed untested; route coverage %d/%d applicable injectable routes tested\n", untested, touched, applicable)
		if gaps := CoverageGaps(state, coverageDenominator(state)); len(gaps) > 0 {
			fmt.Fprintf(&b, "coverage residual (not tested on these endpoints):\n%s", FormatGaps(gaps))
		}
	}
	if state.LeadIdleResets > 0 || state.LeadWindowStartIteration > 0 {
		fmt.Fprintf(&b, "lead handling: idle-tail restarts from new model hypotheses %d/%d; verification window opened at iteration %d\n",
			state.LeadIdleResets, maxLeadIdleResets, state.LeadWindowStartIteration)
	}
	unverified := state.UnverifiedLeadsAtFinish
	if unverified == "" {
		if leads := activeVerificationLeads(state, time.Time{}); len(leads) > 0 {
			unverified = formatLeadList(leads, 8)
		}
	}
	if unverified != "" {
		fmt.Fprintf(&b, "unverified leads at finish (manual follow-up recommended): %s\n", unverified)
	}

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
