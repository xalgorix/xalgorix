package agent

// convergence_finish.go implements the OPTIONAL principled finish
// (XALGORIX_CONVERGE_FINISH, default on). It is inert when the flag is off.
//
// Problem it solves
// -----------------
// taskCoverageComplete closes a generic per-endpoint class task only when EVERY
// applicable endpoint in the coverage denominator is tested for that class. The
// denominator (CoverageBaseline, frozen from DiscoveredEndpoints) is dominated by
// dirbust candidates — mostly non-injectable 404s, static files, VCS/config
// artifacts — so the bar is effectively "test every class on every path content
// discovery ever probed", which the agent never completes. The class tasks never
// reach "completed", the plan is never exhausted, the finish gate never opens, and
// the scan churns to a watchdog that cuts it off mid-coverage (dropping findings
// unpredictably, never firing the completion webhook). The exhaustive bar is the
// "miss nothing" mandate encoded, but taken literally it makes scans never
// converge.
//
// The fix: a principled finish
// ----------------------------
// Once a scan is SATURATED — foundational discovery (recon/dirbust) is done and the
// required injection classes have been exercised across the target past a breadth
// threshold — the remaining per-endpoint/whole-target class tasks, the model's own
// pending specific-endpoint hypotheses, and class-less exploratory tasks all close
// (DispositionCoverageSufficient / DispositionCoverageComplete), but only after a
// no-new-finding tail (convergeFinishIdleLimit) confirms diminishing returns. The
// residual untested (route,class) and (endpoint,class) pairs, plus any class not
// exercised target-wide, are recorded in the report (completion.go), so the tradeoff
// is transparent rather than silent.
//
// Breadth, not per-route percentage, is the coverage gate on purpose: per-route
// coverage measured against the dirbust-polluted baseline is meaningless (reads
// single digits even on a thoroughly tested target), whereas VulnClassesTested is
// set only when a class is genuinely exercised, so class breadth is a reliable
// "the methodology actually ran" signal. Companion Lever A (surface.go) stops
// content-discovery artifacts from owing injection classes at all.
//
// Foundational work is never abandoned: an open recon/dirbust task keeps the scan
// not-saturated, so the finish never fires before the surface is mapped. The model's
// specific-endpoint hypotheses DO close as residual — the finding-idle tail is what
// protects a still-productive scan, not an unbounded planned-hypothesis backlog. With
// the flag off every function here is unreachable (callers are flag-gated) and
// behavior is the legacy path byte-for-byte.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

const (
	// convergeFinishDefaultIdle is the no-new-finding tail (iterations) required
	// at saturation before the principled finish fires. Counted only while the
	// scan is saturated, so a still-productive scan (each new finding, and each
	// new model-recorded hypothesis up to maxLeadIdleResets, resets it) is never
	// cut. 150 proved too short on real targets, where findings are rare and a
	// single lead can take well over 150 iterations to verify.
	convergeFinishDefaultIdle = 500

	// convergeFinishDefaultLeadWindow is the one-time verification window
	// (iterations) granted when the tail elapses while the model still holds
	// recent, high-confidence, unverified leads. It is bounded, so the scan
	// still ends.
	convergeFinishDefaultLeadWindow = 100

	// leadConfidenceFloor is the minimum hypothesis confidence that counts as
	// an active lead for the verification window.
	leadConfidenceFloor = 0.7

	// maxLeadIdleResets bounds how many times a NEW model-recorded hypothesis
	// may restart the no-new-finding tail in one scan, so termination stays
	// guaranteed.
	maxLeadIdleResets = 5

	// convergeFinishClassBreadth is the minimum fraction of required injection
	// classes that must have been exercised target-wide (VulnClassesTested) before
	// a scan is considered saturated. Guards against finishing a scan that barely
	// started the methodology, using the reliable class-breadth signal rather than
	// the dirbust-polluted per-route denominator.
	convergeFinishClassBreadth = 0.60
)

// taskBlocksPrincipledFinish reports whether an open task is concrete FOUNDATIONAL
// work that must be settled before a principled finish: recon and dirbust, because
// coverage is meaningless until the surface is actually mapped. Everything else open
// — generic per-endpoint class tasks, whole-target class tasks, the model's own
// specific-endpoint hypotheses, a stuck auth-session, and class-less exploratory
// tasks — is "soft" and closes at the finish, recorded as residual.
//
// Specific-endpoint LLM hypotheses are intentionally NOT blockers. The model plans
// far more of them than it ever executes — dozens per scan, pulled from a backlog it
// never drains — so treating them as must-complete held the scan open forever (the
// observed non-convergence: recon/dirbust/classes all done, yet ~20 planned
// endpoint-specific hypotheses perpetually pending). They are exactly the untested
// (endpoint, class) pairs the principled finish is approved to close as logged
// residual, and the finding-idle tail (no new finding for convergeFinishDefaultIdle
// iterations) guarantees a scan that is still turning these into findings is never
// cut — only one in genuine diminishing returns is.
func taskBlocksPrincipledFinish(state *ScanState, t *Task) bool {
	if t == nil {
		return false
	}
	switch t.ID {
	case "recon":
		// Block only while recon is genuinely incomplete. The recon TASK status
		// can linger "pending" even after recon is done, because its completion
		// predicate (ComprehensiveReconComplete) is stricter than state.ReconDone;
		// blocking on that stale status would hold a fully-reconned scan open
		// forever. ReconDone is the engine's authoritative "surface is mapped" flag.
		return state == nil || !state.ReconDone
	case "dirbust":
		return state == nil || (!state.DirBustingDone && !state.VulnClassesTested["dirbusting"])
	}
	return false
}

// classExercisedTargetWide reports whether a vuln class has coverage evidence at
// the target level (VulnClassesTested), tolerant of class-name normalization.
func classExercisedTargetWide(state *ScanState, class string) bool {
	if state == nil {
		return false
	}
	if canon := normalizeCoverageClass(class); canon != "" && state.VulnClassesTested[canon] {
		return true
	}
	return state.VulnClassesTested[class]
}

// classCoverageBreadth is the fraction of required injection classes exercised
// target-wide — the reliable coverage gate for the principled finish.
func classCoverageBreadth(state *ScanState) float64 {
	req := requiredCoverageClasses()
	if len(req) == 0 {
		return 1
	}
	tested := 0
	for _, c := range req {
		if classExercisedTargetWide(state, c) {
			tested++
		}
	}
	return float64(tested) / float64(len(req))
}

// saturatedForFinish reports whether a scan has done enough that a principled
// finish is warranted: the iteration floor has passed, no open task is concrete
// blocking work (so the structured methodology and all targeted hypotheses are
// settled), there is at least one soft task to close, and class breadth clears the
// threshold. It does NOT apply the finding-idle tail — the caller
// (autoFinalizeIfPlanComplete) owns that counter so a still-productive saturated
// scan is not cut.
func saturatedForFinish(state *ScanState) bool {
	if state == nil || !state.ConvergeFinish || state.Plan == nil {
		return false
	}
	if state.Iteration < state.MinIterations {
		return false
	}
	sawSoft := false
	for _, t := range state.Plan.Tasks {
		if t.Status != TaskPending && t.Status != TaskActive {
			continue
		}
		if taskBlocksPrincipledFinish(state, t) {
			return false
		}
		sawSoft = true
	}
	if !sawSoft {
		return false
	}
	return classCoverageBreadth(state) >= convergeFinishClassBreadth
}

// closeSoftTasksForFinish closes every remaining soft task at a principled finish
// as DispositionUntestedAtFinish, because it was not executed; phase summaries
// and the completion assessment report it that way. A stuck auth lane stays
// typed blocked/exhausted work. Concrete blocking tasks are never touched. Returns the number closed. Only reached when saturatedForFinish
// held and the finding-idle tail elapsed.
func closeSoftTasksForFinish(state *ScanState) int {
	if state == nil || state.Plan == nil {
		return 0
	}
	closed := 0
	for _, t := range state.Plan.Tasks {
		if t.Status != TaskPending && t.Status != TaskActive {
			continue
		}
		if taskBlocksPrincipledFinish(state, t) {
			continue
		}
		if t.ID == "recon" || t.ID == "dirbust" {
			// Reached here only because the work is actually done (ReconDone /
			// DirBustingDone) but the task status lagged. Mark it COMPLETED — it is,
			// and that keeps the worked-phases telemetry honest.
			t.Status = TaskCompleted
			if t.Notes == "" {
				t.Notes = "engine: " + t.ID + " complete (authoritative state flag set); task status reconciled at principled finish"
			}
			closed++
			continue
		}
		t.Status = TaskSkipped
		switch {
		case t.ID == "auth-session":
			// A stuck auth lane is honest BLOCKED work, not "coverage sufficient":
			// surfacing it as blocked_* makes the terminal status
			// completed_with_blocked_work (resumable) rather than a silent success.
			if state.AuthContextAvailable {
				t.Disposition = DispositionExhausted
				if t.Notes == "" {
					t.Notes = "engine: authenticated testing did not converge within the scan; recorded as residual at principled finish"
				}
			} else {
				t.Disposition = DispositionBlockedMissingAuth
				if t.Notes == "" {
					t.Notes = "engine: authenticated testing not completed (no credentials ingested / auth flow not mapped); recorded as blocked residual at principled finish"
				}
			}
		case t.Origin == "llm" && t.VulnClass != "" && strings.TrimSpace(t.Endpoint) != "":
			t.Disposition = DispositionUntestedAtFinish
			if t.Notes == "" {
				t.Notes = "engine: model-planned endpoint-specific test (" + t.VulnClass + ") was not executed; closed untested at the principled finish"
			}
		case t.VulnClass != "":
			t.Disposition = DispositionUntestedAtFinish
			if t.Notes == "" {
				t.Notes = "engine: " + t.VulnClass + " task was not executed (the class was exercised elsewhere on the target); closed untested at the principled finish, residual endpoints recorded in telemetry"
			}
		default:
			t.Disposition = DispositionUntestedAtFinish
			if t.Notes == "" {
				t.Notes = "engine: exploratory task was not executed; closed untested at the principled finish"
			}
		}
		closed++
	}
	return closed
}

// reconcileLedgerForFinish settles dangling "testing" hypotheses at a principled
// finish. The model moves far more hypotheses to "testing" than it ever closes
// (it claims from a huge backlog and moves on), so after the finding-idle tail
// those are abandoned, not active, work — yet left open they keep the completion
// assessment "incomplete" even though the scan is genuinely done. Marking them
// exhausted (attempt spent without proof) records them as settled residual, so
// the terminal status reads "completed". Only "testing" is touched: queued
// hypotheses were never claimed (and don't gate completion), proven ones are real
// findings, and rejected/blocked/exhausted are already terminal. Flag-gated and a
// no-op without a ledger. Returns the number reconciled.
func reconcileLedgerForFinish(state *ScanState) int {
	if state == nil || !state.ConvergeFinish {
		return 0
	}
	l := ledgerForState(state)
	if l == nil {
		return 0
	}
	owner := ""
	if state.DelegatedAgent {
		owner = state.DelegatedAgentID
	}
	n := 0
	for _, h := range l.All() {
		// Work an engine verifier recorded exploit evidence on is not abandoned
		// residual: it stays open so the report says it was not concluded.
		if h.Status == scanctx.HypothesisTesting && hypothesisBelongsToOwner(h, owner) && !h.HasEngineExploit() {
			if l.SetStatus(h.ID, scanctx.HypothesisExhausted, "claimed but not completed within the scan; closed as residual at principled finish") {
				n++
			}
		}
	}
	return n
}

// untestedAtFinishCount returns how many plan tasks the principled finish closed
// without executing them.
func untestedAtFinishCount(state *ScanState) int {
	if state == nil || state.Plan == nil {
		return 0
	}
	n := 0
	for _, t := range state.Plan.Tasks {
		if isUntestedAtFinish(t) {
			n++
		}
	}
	return n
}

// isModelRecordedHypothesis reports whether a ledger hypothesis was recorded by
// the model itself (record_hypothesis from the coordinator or a specialist),
// rather than generated by the engine from the plan, the discovered surface,
// advisories, HAR imports or verifiers. Engine-generated candidates arrive by
// the hundred, so only the model's own leads may restart the idle tail or hold
// the verification window.
func isModelRecordedHypothesis(h scanctx.Hypothesis) bool {
	return scanctx.IsModelOrigin(h.Origin)
}

// modelHypothesisCount counts the model-recorded hypotheses in the ledger.
func modelHypothesisCount(state *ScanState) int {
	l := ledgerForState(state)
	if l == nil {
		return 0
	}
	n := 0
	for _, h := range l.All() {
		if isModelRecordedHypothesis(h) {
			n++
		}
	}
	return n
}

// activeVerificationLeads returns the unresolved leads the verification window
// waits on, highest confidence first:
//   - the model's recent, high-confidence leads: model-recorded hypotheses that
//     are queued or testing, at or above leadConfidenceFloor, and updated at or
//     after since (a zero since accepts any time);
//   - at any age, work an engine verifier recorded exploit evidence on that is
//     still testing, or proven but not yet reported.
func activeVerificationLeads(state *ScanState, since time.Time) []scanctx.Hypothesis {
	l := ledgerForState(state)
	if l == nil {
		return nil
	}
	unreported := make(map[string]bool)
	for _, id := range provenUnreportedHypothesesForOwner(l, "", state.ScanContextID) {
		unreported[id] = true
	}
	var leads []scanctx.Hypothesis
	for _, h := range l.All() {
		if unreported[h.ID] || (h.Status == scanctx.HypothesisTesting && h.HasEngineExploit()) {
			leads = append(leads, h)
			continue
		}
		if !isModelRecordedHypothesis(h) || h.Confidence < leadConfidenceFloor {
			continue
		}
		if h.Status != scanctx.HypothesisQueued && h.Status != scanctx.HypothesisTesting {
			continue
		}
		if !since.IsZero() && h.UpdatedAt.Before(since) {
			continue
		}
		leads = append(leads, h)
	}
	sort.SliceStable(leads, func(i, j int) bool { return leads[i].Confidence > leads[j].Confidence })
	return leads
}

// formatLeadList renders up to max leads as "H-1 (class /endpoint, 0.80)".
func formatLeadList(leads []scanctx.Hypothesis, max int) string {
	parts := make([]string, 0, len(leads))
	for i, h := range leads {
		if i == max {
			parts = append(parts, fmt.Sprintf("+%d more", len(leads)-max))
			break
		}
		loc := h.VulnClass
		if h.Endpoint != "" {
			loc += " " + h.Endpoint
		}
		parts = append(parts, fmt.Sprintf("%s (%s, %.2f)", h.ID, loc, h.Confidence))
	}
	return strings.Join(parts, ", ")
}

// routeTouchCounts returns, over the coverage denominator, how many routes carry
// at least one applicable canonical injection class (applicable) and how many of
// those have been tested for at least one such class (touched). Reported in the
// finish telemetry for transparency; NOT used as a gate (the dirbust-polluted
// denominator makes the ratio unreliable — see the package comment).
func routeTouchCounts(state *ScanState) (touched, applicable int) {
	if state == nil {
		return 0, 0
	}
	for _, ep := range coverageDenominator(state) {
		var canon []string
		for _, c := range ApplicableClassesForEndpoint(state, ep) {
			if CanonicalVulnClassID(c) != "" {
				canon = append(canon, c)
			}
		}
		if len(canon) == 0 {
			continue
		}
		applicable++
		for _, c := range canon {
			if endpointTestedForClass(state, ep, c) {
				touched++
				break
			}
		}
	}
	return touched, applicable
}
