package agentsgraph

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/storage"
)

type savedAgent struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Task        string    `json:"task"`
	Targets     []string  `json:"targets"`
	Status      string    `json:"status"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Result      string    `json:"result"`
	Error       string    `json:"error"`
	Observed    bool      `json:"observed"`
	Partial     []string  `json:"partial"`
}

type graphCheckpoint struct {
	Version   int          `json:"version"`
	Counter   uint64       `json:"counter"`
	Delegated int          `json:"delegated"`
	Agents    []savedAgent `json:"agents"`
}

func (g *Graph) persistLocked() error {
	if g.persistPath == "" {
		return nil
	}
	saved := graphCheckpoint{Version: 1, Counter: g.counter, Delegated: g.delegated}
	for _, state := range g.agents {
		saved.Agents = append(saved.Agents, savedAgent{
			state.ID, state.Name, state.Task, state.Targets, state.Status,
			state.StartedAt, state.CompletedAt, state.Result, state.Error, state.Observed, state.Partial,
		})
	}
	sort.Slice(saved.Agents, func(i, j int) bool { return saved.Agents[i].ID < saved.Agents[j].ID })
	data, err := json.Marshal(saved)
	if err == nil {
		err = storage.WriteAtomic(g.persistPath, data)
	}
	if err != nil && g.persistErr == nil {
		g.persistErr = err
	}
	return err
}

// SaveCheckpoint also catches failures from asynchronous child completion.
func (g *Graph) SaveCheckpoint() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.persistErr != nil {
		return g.persistErr
	}
	return g.persistLocked()
}

// RestoreCheckpoint restores identities, assignments, results and lifetime
// admission counts without starting runners before root state is available.
func (g *Graph) RestoreCheckpoint(dir string) error {
	if g == nil || dir == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.agents) != 0 {
		return fmt.Errorf("cannot restore an active delegation graph")
	}
	if err := storage.EnsureSecureDir(dir); err != nil {
		return err
	}
	g.persistPath = filepath.Join(dir, "execution-graph.json")
	data, err := os.ReadFile(g.persistPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved graphCheckpoint
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	if saved.Version != 1 || saved.Delegated < len(saved.Agents) {
		return fmt.Errorf("invalid or incompatible delegation checkpoint")
	}
	for _, state := range saved.Agents {
		if state.ID == "" || state.Name == "" || state.Task == "" || g.agents[state.ID] != nil {
			return fmt.Errorf("invalid or duplicate checkpoint agent")
		}
		restored := &subAgentState{
			ID: state.ID, Name: state.Name, Task: state.Task, Targets: state.Targets,
			Status: state.Status, StartedAt: state.StartedAt, CompletedAt: state.CompletedAt,
			Result: state.Result, Error: state.Error, Observed: state.Observed, Partial: state.Partial,
			done: make(chan struct{}),
		}
		switch {
		case state.Status == "queued" || state.Status == "running" || state.Status == "failed" && state.Error == "parent scan stopped":
			restored.Status = "queued"
			restored.CompletedAt = time.Time{}
			restored.Error = ""
			g.queue = append(g.queue, restored)
		case state.Status == "completed" || state.Status == "failed":
			restored.doneOnce.Do(func() { close(restored.done) })
		default:
			return fmt.Errorf("invalid checkpoint agent status %q", state.Status)
		}
		g.agents[state.ID] = restored
	}
	g.counter = saved.Counter
	g.delegated = saved.Delegated
	return nil
}

// ResumeCheckpointedWork runs each unfinished identity once under the same
// concurrency and lifetime contract. Completed lanes remain collectable.
func (g *Graph) ResumeCheckpointedWork() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for !g.stopped && g.ctx.Err() == nil && g.activeAgents < g.maxConcurrent && len(g.queue) > 0 {
		state := g.queue[0]
		g.queue = g.queue[1:]
		state.Status = "running"
		if err := g.persistLocked(); err != nil {
			state.Status = "queued"
			g.queue = append([]*subAgentState{state}, g.queue...)
			return
		}
		g.activeAgents++
		g.wg.Add(1)
		go g.runAgent(state)
	}
}
