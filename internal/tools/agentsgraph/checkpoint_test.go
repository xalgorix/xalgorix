package agentsgraph

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/storage"
)

func TestGraphCheckpointResumesUnfinishedIdentitiesOnce(t *testing.T) {
	dir := t.TempDir()
	saved := graphCheckpoint{Version: 1, Counter: 2, Delegated: 2, Agents: []savedAgent{
		{ID: "done", Name: "completed-lane", Task: "assigned task", Status: "completed", Result: "saved evidence"},
		{ID: "interrupted", Name: "remaining-lane", Task: "remaining task", Status: "running", Targets: []string{"https://example.invalid"}},
	}}
	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.WriteAtomic(filepath.Join(dir, "execution-graph.json"), data); err != nil {
		t.Fatal(err)
	}
	runs := make(chan string, 3)
	g := NewWithConfig(context.Background(), 2, 1, func(_ context.Context, id, _ string, _ []string, _ string) (string, error) {
		runs <- id
		return "continued evidence", nil
	})
	t.Cleanup(g.Stop)
	if err := g.RestoreCheckpoint(dir); err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Fatal("restoration launched work before the root was ready")
	}
	g.ResumeCheckpointedWork()
	g.ResumeCheckpointedWork()
	if !g.WaitStopped(time.Second) {
		t.Fatal("restored lane did not complete")
	}
	if len(runs) != 1 || <-runs != "interrupted" || g.DelegationCount() != 2 {
		t.Fatal("completed work reran or restart reset lifetime admission")
	}
	done, ok := g.snapshot("done", false)
	if !ok || done.Result != "saved evidence" || done.Observed {
		t.Fatalf("completed uncollected result was lost: %+v", done)
	}
}

func TestAsyncCheckpointFailureRemainsVisibleAtRootSafePoint(t *testing.T) {
	dir := t.TempDir()
	g := NewWithConfig(context.Background(), 1, 1, nil)
	t.Cleanup(g.Stop)
	if err := g.RestoreCheckpoint(dir); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	g.persistPath = filepath.Join(dir, "unavailable", "execution-graph.json")
	if err := g.persistLocked(); err == nil {
		t.Fatal("expected unavailable checkpoint directory")
	}
	if err := os.Mkdir(filepath.Join(dir, "unavailable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := g.persistLocked(); err != nil {
		t.Fatal(err)
	}
	g.mu.Unlock()
	if err := g.SaveCheckpoint(); err == nil {
		t.Fatal("a later write hid the earlier asynchronous durability failure")
	}
}
