package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

const planValidationRecoveryLimit = 24

// Track completed work rather than changing task IDs or error text. Reads,
// active-task flips and repeated plan replacements do not restart recovery.
func assessmentProgressFacts(state *ScanState) []string {
	var progress []string
	if state.Plan != nil {
		for _, task := range state.Plan.Tasks {
			if task.Status == TaskCompleted || (task.Status == TaskSkipped && task.Disposition != "") {
				identity := fmt.Sprintf("%d:%s:%s", task.Phase, normalizeCoverageClass(task.VulnClass), task.Endpoint)
				progress = append(progress, "task:"+identity+":"+string(task.Status))
			}
		}
	}
	for endpoint, classes := range state.EndpointClassCoverage {
		for class, covered := range classes {
			if covered {
				progress = append(progress, "coverage:"+endpoint+":"+class)
			}
		}
	}
	for dimension, status := range state.AuthCoverage {
		if status != "" {
			progress = append(progress, "auth:"+dimension+":"+status)
		}
	}
	for dimension, status := range state.ReconCoverage.Dispositions {
		progress = append(progress, "recon:"+dimension+":"+status)
	}
	for dimension, complete := range map[string]bool{
		"dns": state.ReconCoverage.DNSResolved, "services": state.ReconCoverage.ServicesProbed,
		"http": state.ReconCoverage.HTTPProbed, "tech": state.ReconCoverage.TechFingerprinted,
		"crawl": state.ReconCoverage.Crawled, "js": state.ReconCoverage.JSAnalyzed,
		"api": state.ReconCoverage.APISurfaceDiscovered, "params": state.ReconCoverage.ParamDiscovered,
		"history": state.ReconCoverage.HistoricalChecked, "subdomains": state.ReconCoverage.SubdomainEnumerated,
	} {
		if complete {
			progress = append(progress, "recon:"+dimension+":complete")
		}
	}
	for host, complete := range state.ReconCoverage.ContentDiscoveredHosts {
		if complete {
			progress = append(progress, "content:"+host)
		}
	}
	return progress
}

func hookPlanValidationTracker(state *ScanState, args map[string]string) HookResult {
	if state == nil {
		return HookResult{}
	}
	if state.PlanProgressSeen == nil {
		state.PlanProgressSeen = make(map[string]bool)
	}
	for _, fact := range assessmentProgressFacts(state) {
		if !state.PlanProgressSeen[fact] {
			state.PlanProgressSeen[fact] = true
			state.PlanValidationErrors = 0
			state.PlanValidationTurnRecorded = false
		}
	}
	if (args["tool_name"] != "update_plan" && args["tool_name"] != "build_plan") || args["error"] == "" {
		return HookResult{}
	}
	// One model turn can submit many plan calls; count recovery by turn.
	if state.PlanValidationTurnRecorded && state.PlanValidationErrorIteration == state.Iteration {
		return HookResult{}
	}
	state.PlanValidationErrorIteration = state.Iteration
	state.PlanValidationTurnRecorded = true
	state.PlanValidationErrors++
	if state.PlanValidationErrors >= planValidationRecoveryLimit {
		return HookResult{
			StopReason: "stuck_loop_limit",
			EmitMessage: "Scan stopped: repeated plan validation failures made no progress after bounded recovery. " +
				"Assessment remains partial; saved findings are preserved.",
		}
	}
	if state.PlanValidationErrors == 4 || state.PlanValidationErrors == 12 {
		return HookResult{Nudge: "Plan changes keep failing without completed work. Read the current plan and use its exact task IDs, " +
			"required evidence and concrete disposition notes. Changing IDs or repeating rejected transitions cannot satisfy the plan."}
	}
	return HookResult{}
}

func (a *Agent) stopForHook(result HookResult) bool {
	if result.StopReason == "" {
		return false
	}
	content := result.EmitMessage
	if content == "" {
		content = "Scan stopped before complete assessment; saved findings are preserved."
	}
	a.emit(Event{Type: "finished", Content: content, TotalTokens: a.syncBudgetTokens(), Aborted: true, AbortReason: result.StopReason})
	if a.cancel != nil {
		a.cancel()
	}
	return true
}

func (a *Agent) emitContextStop() {
	if deadline, ok := a.scanDeadline(); ok && !time.Now().Before(deadline) {
		a.stopForHook(HookResult{StopReason: "resource_budget", EmitMessage: "Scan stopped: original duration budget exhausted; saved findings are preserved."})
		return
	}
	if a.livenessExpired.Load() || a.semanticIdleRemaining() <= 0 {
		a.stopForHook(HookResult{StopReason: "stuck_loop_limit", EmitMessage: "Scan stopped: no new assessment evidence within the active recovery deadline; saved findings are preserved."})
		return
	}
	a.emit(Event{Type: "finished", Content: "Scan interrupted; unfinished work can resume.", TotalTokens: a.syncBudgetTokens(), Resumable: true})
}

// Accepted evidence advances a durable graph-wide signal. Model turns, logs,
// changed task IDs and successful reads cannot keep a stalled scan alive.
func (a *Agent) updateAssessmentProgress() {
	if a.state == nil || a.scanBudget == nil {
		return
	}
	facts := assessmentProgressFacts(a.state)
	for i := range facts {
		facts[i] = a.delegatedAgentID + ":" + facts[i]
	}
	if a.scanCtx != nil {
		for _, finding := range reporting.GetVulnerabilitiesForContext(a.scanCtx.ID) {
			facts = append(facts, "finding:"+strings.ToLower(finding.Title)+":"+finding.Target+":"+finding.Endpoint)
		}
	}
	a.scanBudget.persistMu.Lock()
	defer a.scanBudget.persistMu.Unlock()
	if a.scanBudget.progressFacts == nil {
		a.scanBudget.progressFacts = make(map[string]bool)
	}
	for _, fact := range facts {
		if !a.scanBudget.progressFacts[fact] {
			a.scanBudget.progressFacts[fact] = true
			a.scanBudget.progress.Add(1)
			a.scanBudget.progressAt = time.Now()
		}
	}
}

func (a *Agent) AssessmentProgress() int {
	if a == nil || a.scanBudget == nil {
		return 0
	}
	return int(a.scanBudget.progress.Load())
}

// LifetimeUsage exposes the restored ledger before the first resumed event.
func (a *Agent) LifetimeUsage() (iterations, toolCalls, tokens int) {
	if a == nil || a.scanBudget == nil {
		return 0, 0, 0
	}
	return a.scanBudget.iterationCount(), a.scanBudget.toolCallCount(), a.scanBudget.tokenCount()
}

const semanticNonProgressLimit = 160

func (a *Agent) semanticIdleRemaining() time.Duration {
	if a.cfg == nil || a.cfg.MaxNonProgressSec <= 0 || a.scanBudget == nil {
		return time.Duration(1<<63 - 1)
	}
	a.scanBudget.persistMu.Lock()
	defer a.scanBudget.persistMu.Unlock()
	if a.scanBudget.progressAt.IsZero() {
		a.scanBudget.progressAt = time.Now()
	}
	return time.Until(a.scanBudget.progressAt.Add(time.Duration(a.cfg.MaxNonProgressSec) * time.Second))
}

// The active idle clock also bounds a blocked model request or tool wait.
// The monitor only cancels work; terminal events and checkpoints stay on the owner loop.
func (a *Agent) startSemanticWatchdog() func() {
	if a.cfg == nil || a.cfg.MaxNonProgressSec <= 0 || a.scanBudget == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.ctx = ctx
	a.client.SetContext(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			remaining := a.semanticIdleRemaining()
			if remaining <= 0 {
				a.livenessExpired.Store(true)
				cancel()
				if a.scanCtx != nil && a.scanCtx.Cancel != nil {
					a.scanCtx.Cancel()
				}
				return
			}
			timer := time.NewTimer(remaining)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}

func (a *Agent) semanticLivenessCheck() HookResult {
	if a.state == nil || a.scanBudget == nil {
		return HookResult{}
	}
	// Once the diminishing-returns finish tail is armed it bounds the scan, and
	// a model spending many turns on one lead is what that tail exists to allow.
	// Ending the scan here as stuck_loop_limit would skip the completion
	// assessment, the residual record and the verification window. The idle
	// clock still restarts every iteration, so the wall-clock watchdog keeps
	// guarding against a single hung model request or tool wait.
	if limit, _ := a.finishTailMode(); limit > 0 {
		a.state.ProgressIdleIterations = 0
		a.state.LastAssessmentProgress = a.AssessmentProgress()
		a.resetProgressClock()
		return HookResult{}
	}
	if a.semanticIdleRemaining() <= 0 {
		// Iteration-driven stall where the wall-clock idle budget also happens to
		// be spent: try to advance past the stuck task before giving up. (The
		// separate time-watchdog goroutine can still cancel the run context on a
		// slow-iterating scan; that path is unchanged and simply stops as before.)
		if a.tryAdvancePastStuck() {
			return HookResult{}
		}
		return HookResult{StopReason: "stuck_loop_limit", EmitMessage: "Scan stopped: active recovery deadline exhausted without new assessment evidence; saved findings are preserved."}
	}
	progress := a.AssessmentProgress()
	if progress > a.state.LastAssessmentProgress {
		a.state.ProgressIdleIterations = 0
		a.state.LastAssessmentProgress = progress
		// Real progress replenishes the advance budget: the recovery bound only
		// trips on CONSECUTIVE advances that each yield nothing.
		a.state.StuckAdvancesSinceProgress = 0
	} else {
		a.state.ProgressIdleIterations++
	}
	if a.state.ProgressIdleIterations >= semanticNonProgressLimit {
		// Before terminating the whole scan, try to skip the current stalled task
		// and continue with the rest of the plan (bounded; flag-gated).
		if a.tryAdvancePastStuck() {
			return HookResult{}
		}
		return HookResult{StopReason: "stuck_loop_limit", EmitMessage: "Scan stopped: bounded recovery produced no new assessment evidence. Assessment remains partial; saved findings are preserved."}
	}
	// Slow-scan safeguard: on a scan whose iterations are slow (seconds each), the
	// 160-iteration counter above may not reach its limit before the wall-clock
	// idle watchdog cancels the run — so a stalled SLOW scan would be KILLED
	// instead of advanced, and never reach its untested tasks. Once most of the
	// wall-clock idle budget is spent with no new progress, fire the advance
	// proactively (while the run context is still alive), so slow stuck scans also
	// skip the stuck task and keep covering the plan. tryAdvancePastStuck is
	// flag-gated and bounded, and resets both idle clocks on success.
	if a.cfg != nil && a.cfg.MaxNonProgressSec > 0 {
		budget := time.Duration(a.cfg.MaxNonProgressSec) * time.Second
		if a.semanticIdleRemaining() <= budget/3 && a.tryAdvancePastStuck() {
			return HookResult{}
		}
	}
	if a.state.ProgressIdleIterations == semanticNonProgressLimit/2 {
		a.appendUserNudge("No new assessment evidence has been validated for many turns. Read the current plan, complete unfinished work with concrete evidence, or record a justified blocked/not-applicable disposition. Repeating reads or changing task IDs does not advance the assessment.")
	}
	return HookResult{}
}

// tryAdvancePastStuck recovers a stalled scan instead of killing it: when the
// feature is enabled and the consecutive-advance budget is not spent, it skips
// the current stuck task and steers the agent to the remaining plan, resets the
// idle counters, and returns true to CONTINUE the scan. It returns false when
// advancing is disabled, out of budget (blocked on everything), or impossible
// (no unfinished work remains), so the caller applies the normal stuck stop.
func (a *Agent) tryAdvancePastStuck() bool {
	if a.cfg == nil || !a.cfg.AdvancePastStuckTasks || a.state == nil {
		return false
	}
	limit := a.cfg.MaxStuckAdvances
	if limit <= 0 {
		limit = 3
	}
	if a.state.StuckAdvancesSinceProgress >= limit {
		return false // blocked on every remaining task — let the scan stop honestly
	}
	if !a.advancePastStuckTask() {
		return false // nothing left to move on to
	}
	a.state.StuckAdvancesSinceProgress++
	a.state.ProgressIdleIterations = 0
	a.resetProgressClock()
	return true
}

// advancePastStuckTask marks the current stalled task terminal (blocked, NOT
// completed) and nudges the agent to the remaining unfinished tasks, so a scan
// fixated on one un-completable task recovers coverage of the rest of its plan.
// Returns false when no unfinished work remains to advance to (the normal
// finish/finalize path should run instead).
func (a *Agent) advancePastStuckTask() bool {
	if a.state == nil || a.state.Plan == nil {
		return false
	}
	var active *Task
	remaining := 0
	for _, t := range a.state.Plan.Tasks {
		switch t.Status {
		case TaskActive:
			if active == nil {
				active = t
				continue
			}
			remaining++
		case TaskPending:
			remaining++
		}
	}
	if remaining == 0 {
		return false // only the stalled task (if any) is left; nothing to move on to
	}
	skipped := "the stalled task"
	if active != nil {
		active.Status = TaskSkipped
		active.Disposition = DispositionBlockedNoProgress
		note := fmt.Sprintf("auto-advanced: no new assessment evidence for %d iterations; skipped to preserve coverage of %d remaining task(s)", semanticNonProgressLimit, remaining)
		if active.Notes != "" {
			active.Notes += " | " + note
		} else {
			active.Notes = note
		}
		skipped = fmt.Sprintf("task %q (phase %d)", active.ID, active.Phase)
	}
	a.appendUserNudge(fmt.Sprintf("STUCK-TASK RECOVERY: %s produced no new assessment evidence for many turns and is now marked blocked_no_progress — do NOT keep retrying it. Read the current plan and move to a DIFFERENT unfinished task (%d remain), testing it with concrete requests and recording real evidence. If a task is genuinely inapplicable or blocked, record its typed not_applicable/blocked_* disposition with a concrete surface fact.", skipped, remaining))
	return true
}

// resetProgressClock moves only the wall-clock idle deadline forward WITHOUT
// recording a (non-existent) progress fact, so the time watchdog does not kill
// the scan immediately after advance-past-stuck skips a stalled task.
func (a *Agent) resetProgressClock() {
	if a.scanBudget == nil {
		return
	}
	a.scanBudget.persistMu.Lock()
	a.scanBudget.progressAt = time.Now()
	a.scanBudget.persistMu.Unlock()
}

// pauseIdleClock moves the wall-clock idle deadline forward by d, so time spent
// waiting on the LLM provider (rate-limit, quota, overload or error backoff) is
// not counted as time without assessment progress. Call it before the wait so
// the watchdog goroutine does not fire mid-backoff. progressAt is checkpointed,
// so a scan paused by a provider outage resumes with the idle budget it had.
func (a *Agent) pauseIdleClock(d time.Duration) {
	if a.scanBudget == nil || d <= 0 {
		return
	}
	a.scanBudget.persistMu.Lock()
	if a.scanBudget.progressAt.IsZero() {
		a.scanBudget.progressAt = time.Now()
	}
	a.scanBudget.progressAt = a.scanBudget.progressAt.Add(d)
	a.scanBudget.persistMu.Unlock()
}

// defaultPlanCompleteFindingIdle is how many iterations a root scan may run
// after its plan is fully exhausted without proving any NEW finding before the
// engine finalizes the assessment. It is generous on purpose: it only bounds
// the no-new-findings tail AFTER the entire structured methodology is already
// done, so a still-productive scan (each new finding resets the counter) is
// never cut, while an exhausted scan that keeps re-testing covered surface for
// no new evidence can no longer run for many thousands of idle iterations.
const defaultPlanCompleteFindingIdle = 600

func (a *Agent) planCompleteFindingIdleLimit() int {
	if a.cfg != nil && a.cfg.PlanCompleteFindingIdle != 0 {
		return a.cfg.PlanCompleteFindingIdle // negative disables (returned as-is; checked by caller)
	}
	return defaultPlanCompleteFindingIdle
}

// autoFinalizeIfPlanComplete ends a root scan once its structural plan is
// exhausted (no pending/active tasks) AND no new finding has been validated for
// planCompleteFindingIdleLimit() iterations. It is the fix for unbounded tails:
// the semantic liveness clock above is kept alive by any new coverage fact, so
// a scan that has completed its whole plan but keeps churning already-covered
// endpoints (phase-21 "novel discovery") never idles out even while proving
// nothing. This counter, by contrast, only advances once the plan is done and
// is reset solely by a NEW finding. When it fires the scan is finalized through
// the same honest terminal assessment as a normal finish, so saved findings and
// the real completion status are preserved. Returns true when it finalized (the
// caller must then return from the run loop). Must be called exactly once per
// iteration — it mutates the idle counter.
func (a *Agent) autoFinalizeIfPlanComplete() bool {
	limit, saturated := a.finishTailMode()
	if limit <= 0 {
		return false // not in a terminal mode, or that mode's tail is disabled
	}

	cur := 0
	if a.scanCtx != nil {
		cur = len(reporting.GetVulnerabilitiesForContext(a.scanCtx.ID))
	}
	if cur > a.state.LastFindingCount {
		a.state.LastFindingCount = cur
		a.state.FindingIdleIterations = 0
		a.state.FindingIdleSince = time.Time{}
		return false
	}
	if a.restartIdleTailOnNewLead() {
		return false
	}
	a.state.FindingIdleIterations++
	if a.state.FindingIdleIterations == 1 {
		a.state.FindingIdleSince = time.Now()
	}
	if a.state.FindingIdleIterations < limit {
		return false
	}
	if a.leadVerificationWindowHolds() {
		return false
	}
	// Record the model's still-open leads before the ledger is settled, so the
	// telemetry can list them for manual follow-up.
	if a.state.ConvergeFinish {
		if leads := activeVerificationLeads(a.state, time.Time{}); len(leads) > 0 {
			a.state.UnverifiedLeadsAtFinish = formatLeadList(leads, 8)
		}
	}
	// A saturated (not fully-exhausted) finish closes the remaining soft tasks so
	// the plan reaches a terminal state and the residual (route,class) pairs are
	// recorded before the completion assessment runs.
	if saturated {
		closeSoftTasksForFinish(a.state)
	}
	// Settle dangling "testing" hypotheses as residual so the terminal status is
	// not held "incomplete" by an undrained claim backlog (flag-gated; no-op when
	// ConvergeFinish is off).
	reconcileLedgerForFinish(a.state)
	a.emitPlanCompleteFinish(cur, saturated)
	return true
}

// finishTailMode reports whether a root scan is in a terminal mode whose
// no-new-finding tail bounds it, and that tail's length (<= 0: no tail armed).
// Legacy: the plan is fully exhausted (no pending/active work). ConvergeFinish:
// the plan is SATURATED (saturated=true) — the only open work is generic
// per-endpoint class coverage (and class-less exploratory tasks) past the
// class-breadth threshold, i.e. the unachievable every-route×every-class bar is
// in diminishing returns. Neither mode applies while concrete work remains.
func (a *Agent) finishTailMode() (limit int, saturated bool) {
	if a.state == nil || a.scanBudget == nil || a.state.DelegatedAgent {
		return 0, false // root scans only; specialists close their own lane
	}
	if a.state.Iteration < a.state.MinIterations {
		return 0, false
	}
	if a.state.Plan == nil || len(a.state.Plan.Tasks) == 0 {
		return 0, false
	}
	if _, _, _, unfinished := a.PlanDisposition(); unfinished == 0 {
		return a.planCompleteFindingIdleLimit(), false
	}
	if !saturatedForFinish(a.state) {
		return 0, false
	}
	return a.convergeFinishIdleLimit(), true
}

// restartIdleTailOnNewLead restarts the finding-idle tail when the model has
// recorded a NEW hypothesis since the last check: a scan that is still raising
// fresh leads is not in diminishing returns, even before any is validated.
// Only model-recorded hypotheses count (engine-generated candidates arrive by
// the hundred), only while a tail is running, and at most maxLeadIdleResets
// times per scan so termination stays guaranteed. ConvergeFinish-gated; the
// legacy plan-exhausted path is unchanged. Returns true when it restarted.
func (a *Agent) restartIdleTailOnNewLead() bool {
	if !a.state.ConvergeFinish {
		return false
	}
	n := modelHypothesisCount(a.state)
	prev := a.state.LastModelHypothesisCount
	a.state.LastModelHypothesisCount = n
	if n <= prev || a.state.FindingIdleIterations == 0 {
		return false // no new lead, or no tail running yet (baseline only)
	}
	if a.state.LeadIdleResets >= maxLeadIdleResets {
		return false
	}
	a.state.LeadIdleResets++
	a.state.FindingIdleIterations = 0
	a.state.FindingIdleSince = time.Time{}
	a.emit(Event{Type: "message", Content: fmt.Sprintf("🔁 New hypothesis recorded: the diminishing-returns tail restarted (%d/%d restarts used).", a.state.LeadIdleResets, maxLeadIdleResets), TotalTokens: a.syncBudgetTokens()})
	return true
}

// leadVerificationWindowHolds grants ONE bounded verification window when the
// tail elapses while the model still holds recent, high-confidence, unverified
// leads. The model is asked to conclude each lead (report it if the evidence
// meets the reporting bar, otherwise reject it) instead of the scan closing
// mid-verification. The window ends after convergeLeadWindow iterations, or
// earlier once none of those leads is open. ConvergeFinish-gated.
func (a *Agent) leadVerificationWindowHolds() bool {
	if !a.state.ConvergeFinish {
		return false
	}
	window := a.convergeLeadWindow()
	if window <= 0 {
		return false
	}
	if a.state.LeadWindowStartIteration > 0 {
		// Count the turns the window actually held rather than the iteration
		// delta: provider retries advance the iteration number without giving
		// the model a turn, and must not use up the window.
		a.state.LeadWindowIterations++
		if a.state.LeadWindowIterations >= window {
			return false
		}
		return len(activeVerificationLeads(a.state, a.state.LeadWindowSince)) > 0
	}
	leads := activeVerificationLeads(a.state, a.state.FindingIdleSince)
	if len(leads) == 0 {
		return false
	}
	start := a.state.Iteration
	if start < 1 {
		start = 1
	}
	a.state.LeadWindowStartIteration = start
	a.state.LeadWindowSince = a.state.FindingIdleSince
	directive := fmt.Sprintf("⏳ VERIFICATION WINDOW (%d iterations): no new finding has been validated for the diminishing-returns tail, so the engine will finalize the assessment after this window. Before then, conclude each open lead: %s. For each one, either verify it and report it with report_vulnerability if the evidence meets the normal reporting standard, or reject it with update_hypothesis and a one-line reason. Do not start unrelated work.",
		window, formatLeadList(leads, 8))
	a.appendUserNudge(directive)
	a.emit(Event{Type: "message", Content: directive, TotalTokens: a.syncBudgetTokens()})
	return true
}

// convergeLeadWindow is the verification-window length. A nonzero cfg override
// wins (negative disables, surfaced as <= 0); otherwise the built-in default.
func (a *Agent) convergeLeadWindow() int {
	if a.cfg != nil && a.cfg.ConvergeFinishLeadWindow != 0 {
		return a.cfg.ConvergeFinishLeadWindow
	}
	return convergeFinishDefaultLeadWindow
}

// convergeFinishIdleLimit is the no-new-finding tail for the ConvergeFinish
// saturated finish. A nonzero cfg override wins (negative disables, surfaced as
// <= 0 to the caller); otherwise the built-in default applies.
func (a *Agent) convergeFinishIdleLimit() int {
	if a.cfg != nil && a.cfg.ConvergeFinishIdle != 0 {
		return a.cfg.ConvergeFinishIdle
	}
	return convergeFinishDefaultIdle
}

// emitPlanCompleteFinish finalizes a plan-complete, finding-idle scan through
// the same honest terminal path as a model-issued finish (authoritative
// summary, completion-status assessment, telemetry), so the terminal event is
// indistinguishable from a normal graceful completion and never loses findings.
func (a *Agent) emitPlanCompleteFinish(findingCount int, saturated bool) {
	idle := a.state.FindingIdleIterations
	content := fmt.Sprintf("Assessment finalized: the structural plan is fully exhausted and no new finding was validated in the last %d iterations (diminishing-returns tail). Findings already reported are preserved.", idle)
	if saturated {
		// The saturated finish closes work it never ran; say so instead of
		// claiming the plan was exhausted.
		touched, applicable := routeTouchCounts(a.state)
		content = fmt.Sprintf("Assessment finalized at coverage saturation: no new finding was validated in the last %d iterations (diminishing-returns tail). %d plan task(s) were closed WITHOUT being executed and are recorded as untested residual; %d/%d applicable injectable routes were tested. Findings already reported are preserved.",
			idle, untestedAtFinishCount(a.state), touched, applicable)
	}
	content = authoritativeFinishSummary(content, findingCount)
	status, reasons := settleCompletion(a.state)
	if status != CompletionStatusCompleted {
		content += "\n\n" + formatIncompleteSummary(status, reasons)
	}
	if summary := scanTelemetrySummary(a.state, status, reasons); summary != "" {
		a.emit(Event{Type: "message", Content: summary, TotalTokens: a.syncBudgetTokens()})
	}
	a.emit(Event{Type: "finished", Content: content, TotalTokens: a.syncBudgetTokens()})
}
