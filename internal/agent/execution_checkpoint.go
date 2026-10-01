package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/storage"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

const executionCheckpointVersion = 1

type executionCheckpoint struct {
	Version   int                 `json:"version"`
	ScanID    string              `json:"scan_id"`
	AgentID   string              `json:"agent_id"`
	UpdatedAt time.Time           `json:"updated_at"`
	State     *ScanState          `json:"state"`
	Terminal  *terminalCheckpoint `json:"terminal,omitempty"`
}

type terminalCheckpoint struct {
	Content string `json:"content"`
	Aborted bool   `json:"aborted"`
	Reason  string `json:"reason,omitempty"`
}

type budgetCheckpoint struct {
	Version       int             `json:"version"`
	ScanID        string          `json:"scan_id"`
	StartedAt     time.Time       `json:"started_at"`
	Iterations    int             `json:"iterations"`
	ToolCalls     int             `json:"tool_calls"`
	Tokens        int             `json:"tokens"`
	Progress      int             `json:"progress"`
	ProgressFacts map[string]bool `json:"progress_facts,omitempty"`
	ProgressAt    time.Time       `json:"progress_at,omitempty"`
	UpdatedAt     time.Time       `json:"updated_at,omitempty"`
}

// UnmarshalJSON rebuilds the executable index; serialized task data alone
// cannot answer update_plan lookups after a restart.
func (p *Plan) UnmarshalJSON(data []byte) error {
	type wire Plan
	var saved wire
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	restored := NewPlan()
	for _, task := range saved.Tasks {
		if task == nil || !restored.add(task) {
			return fmt.Errorf("invalid or duplicate checkpoint task")
		}
		switch task.Status {
		case TaskPending, TaskActive, TaskCompleted, TaskSkipped:
		default:
			return fmt.Errorf("invalid checkpoint task status %q", task.Status)
		}
	}
	*p = *restored
	return nil
}

func (a *Agent) executionCheckpointPath() string {
	if a.scanCtx == nil || a.scanCtx.ScanDir == "" {
		return ""
	}
	if a.delegatedAgentID == "" {
		return filepath.Join(a.scanCtx.ScanDir, "execution.json")
	}
	name := fmt.Sprintf("execution-agent-%x.json", sha256.Sum256([]byte(a.delegatedAgentID)))
	return filepath.Join(a.scanCtx.ScanDir, name)
}

// SetResumeBudget conservatively seeds legacy scans whose executable state
// was never checkpointed. It does not invent completed work from narrative.
func (a *Agent) SetResumeBudget(iterations, toolCalls, tokens int, startedAt string) {
	a.SetInitialIteration(iterations)
	if a.scanBudget == nil {
		return
	}
	if toolCalls > a.scanBudget.toolCallCount() {
		a.scanBudget.toolCalls.Store(int64(toolCalls))
	}
	if tokens > a.scanBudget.tokenCount() {
		a.scanBudget.tokens.Store(int64(tokens))
	}
	if started, err := time.Parse(time.RFC3339Nano, startedAt); err == nil {
		a.scanBudget.restoreStart(started)
	}
}

func (b *scanBudget) restoreStart(started time.Time) {
	if started.IsZero() {
		return
	}
	b.startOnce.Do(func() {})
	b.startedMu.Lock()
	if b.startedAt.IsZero() || started.Before(b.startedAt) {
		b.startedAt = started
	}
	b.startedMu.Unlock()
}

func (b *scanBudget) saveCheckpoint(dir, scanID string) error {
	if b == nil {
		return nil
	}
	b.persistMu.Lock()
	defer b.persistMu.Unlock()
	b.startedMu.RLock()
	started := b.startedAt
	b.startedMu.RUnlock()
	data, err := json.Marshal(budgetCheckpoint{Version: executionCheckpointVersion, ScanID: scanID, StartedAt: started,
		Iterations: b.iterationCount(), ToolCalls: b.toolCallCount(), Tokens: b.tokenCount(),
		Progress: int(b.progress.Load()), ProgressFacts: b.progressFacts,
		ProgressAt: b.progressAt, UpdatedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	return storage.WriteAtomic(filepath.Join(dir, "execution-budget.json"), data)
}

func (b *scanBudget) loadCheckpoint(dir, scanID string) error {
	if b == nil {
		return nil
	}
	b.persistMu.Lock()
	defer b.persistMu.Unlock()
	data, err := os.ReadFile(filepath.Join(dir, "execution-budget.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved budgetCheckpoint
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	if saved.Version != executionCheckpointVersion || saved.ScanID != scanID || saved.Iterations < 0 || saved.ToolCalls < 0 || saved.Tokens < 0 || saved.Progress < 0 {
		return fmt.Errorf("invalid or incompatible budget checkpoint")
	}
	// A record may have captured an event newer than this ledger. Preserve the
	// larger spent allowance rather than granting it again after a crash.
	b.restoreStart(saved.StartedAt)
	b.iterations.Store(int64(max(saved.Iterations, b.iterationCount())))
	b.toolCalls.Store(int64(max(saved.ToolCalls, b.toolCallCount())))
	b.tokens.Store(int64(max(saved.Tokens, b.tokenCount())))
	b.progress.Store(int64(saved.Progress))
	b.progressFacts = saved.ProgressFacts
	if !saved.ProgressAt.IsZero() && !saved.UpdatedAt.IsZero() {
		if saved.ProgressAt.After(saved.UpdatedAt) {
			return fmt.Errorf("invalid checkpoint progress clock")
		}
		// Retain spent active idle time without charging a paused server's downtime.
		b.progressAt = time.Now().Add(-saved.UpdatedAt.Sub(saved.ProgressAt))
	}
	return nil
}

// RestoreExecutionCheckpoint must run before source preparation or target
// activity. Missing legacy state is distinct from corrupt modern state.
func (a *Agent) RestoreExecutionCheckpoint() (bool, error) {
	if a.checkpointLoaded {
		return a.executionRestored, nil
	}
	path := a.executionCheckpointPath()
	if path == "" {
		a.checkpointLoaded = true
		return false, nil
	}
	if a.delegatedAgentID == "" {
		if err := reporting.RestoreContext(a.scanCtx.ID, a.scanCtx.ScanDir, a.resumeFindings); err != nil {
			return false, err
		}
		if err := a.scanBudget.loadCheckpoint(a.scanCtx.ScanDir, a.scanCtx.ID); err != nil {
			return false, err
		}
		if err := a.scanCtx.Coverage.LoadCheckpoint(a.scanCtx.ScanDir); err != nil {
			return false, err
		}
		if a.ownsAgentGraph && a.agentGraph != nil {
			if err := a.agentGraph.RestoreCheckpoint(a.scanCtx.ScanDir); err != nil {
				return false, err
			}
		}
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		a.checkpointLoaded = true
		return false, nil
	}
	if err != nil {
		return false, err
	}
	state := NewScanState()
	saved := executionCheckpoint{State: state}
	if err := json.Unmarshal(data, &saved); err != nil {
		return false, err
	}
	if saved.Version != executionCheckpointVersion || saved.ScanID != a.scanCtx.ID || saved.AgentID != a.delegatedAgentID || saved.State == nil {
		return false, fmt.Errorf("invalid or incompatible execution checkpoint")
	}
	state = saved.State
	state.ScanContextID = a.scanCtx.ID
	if saved.Terminal == nil {
		state.CompletionStatus = ""
	}
	state.TargetUnresponsiveSince = time.Time{}
	state.ConsecutiveTargetErrors = 0
	state.BrowserAuthContext = false
	state.ReconCoverage.Attempted = make(map[string]bool)
	state.ReconCoverage.ContentDiscoveryAttempts = make(map[string]bool)
	state.LastPlanBrief = "" // the fresh conversation still needs the restored plan
	a.state = state
	a.terminalOutcome.Store(saved.Terminal)
	a.initialIter = state.Iteration + 1
	a.executionRestored = true
	a.checkpointLoaded = true
	return true, nil
}

// Safe points run on the owning agent loop after a tool result's evidence has
// been validated. No event-consumer goroutine reads mutable plan data here.
func (a *Agent) saveExecutionCheckpoint() error {
	a.updateAssessmentProgress()
	a.publishAssessmentSnapshot()
	path := a.executionCheckpointPath()
	if path == "" || a.state == nil {
		return nil
	}
	if err := storage.EnsureSecureDir(a.scanCtx.ScanDir); err != nil {
		return err
	}
	a.syncBudgetTokens()
	if err := a.scanBudget.saveCheckpoint(a.scanCtx.ScanDir, a.scanCtx.ID); err != nil {
		return err
	}
	if err := a.scanCtx.Coverage.SaveCheckpoint(a.scanCtx.ScanDir); err != nil {
		return err
	}
	if a.ownsAgentGraph {
		if err := a.agentGraph.SaveCheckpoint(); err != nil {
			return err
		}
	}
	data, err := json.Marshal(executionCheckpoint{executionCheckpointVersion, a.scanCtx.ID, a.delegatedAgentID, time.Now().UTC(), a.state, a.terminalOutcome.Load()})
	if err != nil {
		return err
	}
	return storage.WriteAtomic(path, data)
}

func (a *Agent) checkpointOrStop() bool {
	if err := a.saveExecutionCheckpoint(); err != nil {
		a.stopForHook(HookResult{StopReason: "checkpoint_write_failed", EmitMessage: "Scan stopped: execution checkpoint could not be saved; existing findings are preserved."})
		return false
	}
	return true
}

func (a *Agent) resumePlanContext() {
	if a.state.Plan != nil {
		var tasks strings.Builder
		for _, task := range a.state.Plan.Tasks {
			fmt.Fprintf(&tasks, "  %s: %s [phase %d, %s] %s\n", task.ID, task.Status, task.Phase, task.VulnClass, task.Title)
		}
		a.appendUserNudge("Execution checkpoint restored. Continue unfinished tasks using these exact IDs; completed tasks and validated recon/coverage remain authoritative. Re-establish live authentication before unfinished authenticated work. Use read_plan for stored notes and evidence requirements.\n" + tasks.String() + FormatPlan(a.state.Plan, nil))
	}
}

// SetResumeFindings supplies the legacy record fallback while the private
// finding checkpoint retains newer accepted reports and their identities.
func (a *Agent) SetResumeFindings(findings []reporting.Vulnerability) {
	a.resumeFindings = append([]reporting.Vulnerability(nil), findings...)
}
