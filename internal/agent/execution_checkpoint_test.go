package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestExecutionCheckpointRestoresPlanEvidenceAndSpentBudget(t *testing.T) {
	dir := t.TempDir()
	prior := scanctx.New("continuation", dir)
	t.Cleanup(prior.Close)
	state := NewScanState()
	state.Plan = NewPlan()
	state.Plan.add(&Task{ID: "tested", Phase: 6, VulnClass: "sqli", Status: TaskCompleted})
	state.Plan.add(&Task{ID: "remaining", Phase: 7, VulnClass: "xss", Status: TaskActive})
	state.PlanBuilt = true
	state.ReconCoverage.HTTPProbed = true
	state.ReconCoverage.Crawled = true
	state.ReconCoverage.Dispositions["service_discovery"] = "blocked"
	state.ReconCoverage.Attempted["js_analysis"] = true
	state.EndpointClassCoverage["/search"] = map[string]bool{"sqli": true}
	state.AuthCoverage["token_expiry"] = "complete"
	state.Iteration = 4
	prior.Coverage.Mark("/search", "xss")
	prior.Coverage.MarkVerified("/search", "sqli")
	a := &Agent{scanCtx: prior, state: state, scanBudget: newScanBudget()}
	started := time.Now().Add(-time.Hour).UTC()
	a.SetResumeBudget(5, 7, 100, started.Format(time.RFC3339Nano))
	if err := a.saveExecutionCheckpoint(); err != nil {
		t.Fatal(err)
	}

	resumed := scanctx.New("continuation", dir)
	t.Cleanup(resumed.Close)
	b := &Agent{scanCtx: resumed, scanBudget: newScanBudget(), cfg: &config.Config{MaxDurationSec: 600}}
	restored, err := b.RestoreExecutionCheckpoint()
	if err != nil || !restored {
		t.Fatalf("checkpoint restore: %t %v", restored, err)
	}
	if b.state.Plan.Get("tested").Status != TaskCompleted || b.state.Plan.Get("remaining").Status != TaskActive {
		t.Fatal("task identities, index or dispositions were lost")
	}
	if !b.state.ReconCoverage.HTTPProbed || !b.state.ReconCoverage.Crawled || b.state.AuthCoverage["token_expiry"] != "complete" || !b.state.EndpointClassCoverage["/search"]["sqli"] {
		t.Fatal("validated recon/auth/coverage was lost")
	}
	if b.state.ReconCoverage.Attempted["js_analysis"] {
		t.Fatal("an interrupted attempt was restored as in-flight work")
	}
	if !resumed.Coverage.Has("/search", "xss") || resumed.Coverage.HasVerified("/search", "xss") || !resumed.Coverage.HasVerified("/search", "sqli") {
		t.Fatal("shared executed and verifier-attributed evidence lost their distinction")
	}
	b.scanBudget.start()
	if b.scanBudget.reserveIteration(5) || b.scanBudget.reserveToolCalls(1, 7) != 0 || b.scanBudget.tokenCount() != 100 {
		t.Fatal("restart granted additional spent allowance")
	}
	deadline, ok := b.scanDeadline()
	if !ok || !deadline.Equal(started.Add(600*time.Second)) {
		t.Fatalf("restart reset duration clock: %s", deadline)
	}
}

func TestCorruptExecutionCheckpointStopsBeforeTargetWork(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "execution.json")
	corrupt := []byte(`{"version":1,"scan_id":"other-scan","state":{}}`)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	sctx := scanctx.New("this-scan", dir)
	t.Cleanup(sctx.Close)
	events := make(chan Event, 4)
	a := &Agent{scanCtx: sctx, scanBudget: newScanBudget(), events: events, ctx: context.Background()}
	a.Run([]string{"https://example.invalid"}, "")
	event := <-events
	if !event.Aborted || event.AbortReason != "checkpoint_restore_failed" {
		t.Fatalf("corrupt checkpoint was silently treated as a fresh scan: %+v", event)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != string(corrupt) {
		t.Fatal("failed restoration overwrote the recoverable checkpoint")
	}
}

func TestLegacyIterationSeedConsumesSharedAllowance(t *testing.T) {
	a := &Agent{scanBudget: newScanBudget()}
	a.SetInitialIteration(5)
	if a.scanBudget.reserveIteration(5) {
		t.Fatal("legacy restart granted fresh iterations")
	}
}

func TestBudgetCheckpointCannotDisableOrExtendDuration(t *testing.T) {
	for _, savedStart := range []time.Time{{}, time.Now().Add(-time.Minute)} {
		t.Run(savedStart.String(), func(t *testing.T) {
			dir := t.TempDir()
			prior := newScanBudget()
			prior.restoreStart(savedStart)
			if err := prior.saveCheckpoint(dir, "budget-continuity"); err != nil {
				t.Fatal(err)
			}
			resumed := newScanBudget()
			original := time.Now().Add(-time.Hour)
			resumed.restoreStart(original)
			if err := resumed.loadCheckpoint(dir, "budget-continuity"); err != nil {
				t.Fatal(err)
			}
			resumed.start()
			a := &Agent{scanBudget: resumed, cfg: &config.Config{MaxDurationSec: 600}}
			deadline, ok := a.scanDeadline()
			if !ok || !deadline.Equal(original.Add(600*time.Second)) {
				t.Fatalf("checkpoint disabled or extended original duration: %s", deadline)
			}
		})
	}
	budget := newScanBudget()
	dir := t.TempDir()
	if err := budget.saveCheckpoint(dir, "missing-start"); err != nil {
		t.Fatal(err)
	}
	resumed := newScanBudget()
	if err := resumed.loadCheckpoint(dir, "missing-start"); err != nil {
		t.Fatal(err)
	}
	resumed.start()
	if _, started := resumed.elapsed(); !started {
		t.Fatal("missing timestamp consumed the initialization latch")
	}
}

func TestCheckpointedTerminalOutcomeDoesNotRepeatWork(t *testing.T) {
	dir := t.TempDir()
	sctx := scanctx.New("terminal", dir)
	t.Cleanup(sctx.Close)
	a := &Agent{scanCtx: sctx, scanBudget: newScanBudget(), state: NewScanState()}
	a.terminalOutcome.Store(&terminalCheckpoint{Content: "partial result", Aborted: true, Reason: "stuck_loop_limit"})
	if err := a.saveExecutionCheckpoint(); err != nil {
		t.Fatal(err)
	}
	resumed := scanctx.New("terminal", dir)
	t.Cleanup(resumed.Close)
	events := make(chan Event, 4)
	b := &Agent{scanCtx: resumed, scanBudget: newScanBudget(), events: events, ctx: context.Background()}
	b.Run([]string{"https://example.invalid"}, "")
	event := <-events
	if event.Type != "finished" || !event.Aborted || event.AbortReason != "stuck_loop_limit" {
		t.Fatalf("terminal checkpoint was re-executed: %+v", event)
	}
}

func TestShutdownCheckpointRemainsExecutable(t *testing.T) {
	dir := t.TempDir()
	sctx := scanctx.New("shutdown-resume", dir)
	t.Cleanup(sctx.Close)
	ctx, cancel := context.WithCancel(context.Background())
	state := NewScanState()
	state.Plan = NewPlan()
	state.Plan.add(&Task{ID: "done", Phase: 6, VulnClass: "sqli", Status: TaskCompleted})
	state.Plan.add(&Task{ID: "next", Phase: 7, VulnClass: "xss", Status: TaskActive})
	state.ReconCoverage.HTTPProbed = true
	a := &Agent{scanCtx: sctx, state: state, scanBudget: newScanBudget(), ctx: ctx, events: make(chan Event, 1), checkpointLoaded: true}
	cancel()
	a.emitContextStop()
	if event := <-a.events; !event.Resumable || event.Aborted {
		t.Fatalf("external shutdown became a terminal assessment: %+v", event)
	}
	if err := a.saveExecutionCheckpoint(); err != nil {
		t.Fatal(err)
	}
	b := &Agent{scanCtx: sctx, scanBudget: newScanBudget()}
	if restored, err := b.RestoreExecutionCheckpoint(); err != nil || !restored {
		t.Fatalf("restore after shutdown: %t %v", restored, err)
	}
	if b.terminalOutcome.Load() != nil || b.state.Plan.Get("next").Status != TaskActive || !b.state.ReconCoverage.HTTPProbed {
		t.Fatal("restart lost executable work or replayed a false terminal result")
	}
}

func TestPassiveReconGuardSurvivesCheckpoint(t *testing.T) {
	dir := t.TempDir()
	sctx := scanctx.New("passive-resume", dir)
	t.Cleanup(sctx.Close)
	a := &Agent{scanCtx: sctx, state: NewScanState(), scanBudget: newScanBudget(), reconMode: "passive", scanIntensity: "active"}
	a.passiveReconPassiveLookups = 5
	a.passiveReconSourceKeys = map[string]bool{"public_archive": true, "registry": true}
	a.finishPassiveReconGuard()
	if err := a.saveExecutionCheckpoint(); err != nil {
		t.Fatal(err)
	}
	b := &Agent{scanCtx: sctx, scanBudget: newScanBudget(), reconMode: "passive", scanIntensity: "active"}
	if _, err := b.RestoreExecutionCheckpoint(); err != nil {
		t.Fatal(err)
	}
	b.resetPassiveReconGuardForRun()
	if !b.passiveReconGuardDone || b.passiveReconGuardActive || b.passiveReconPassiveLookups != 5 || len(b.passiveReconSourceKeys) != 2 {
		t.Fatal("restart restarted completed passive reconnaissance")
	}
}
