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
		}
	}
	if (args["tool_name"] != "update_plan" && args["tool_name"] != "build_plan") || args["error"] == "" {
		return HookResult{}
	}
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
	if a.semanticIdleRemaining() <= 0 {
		return HookResult{StopReason: "stuck_loop_limit", EmitMessage: "Scan stopped: active recovery deadline exhausted without new assessment evidence; saved findings are preserved."}
	}
	progress := a.AssessmentProgress()
	if progress > a.state.LastAssessmentProgress {
		a.state.ProgressIdleIterations = 0
		a.state.LastAssessmentProgress = progress
	} else {
		a.state.ProgressIdleIterations++
	}
	if a.state.ProgressIdleIterations >= semanticNonProgressLimit {
		return HookResult{StopReason: "stuck_loop_limit", EmitMessage: "Scan stopped: bounded recovery produced no new assessment evidence. Assessment remains partial; saved findings are preserved."}
	}
	if a.state.ProgressIdleIterations == semanticNonProgressLimit/2 {
		a.appendUserNudge("No new assessment evidence has been validated for many turns. Read the current plan, complete unfinished work with concrete evidence, or record a justified blocked/not-applicable disposition. Repeating reads or changing task IDs does not advance the assessment.")
	}
	return HookResult{}
}
