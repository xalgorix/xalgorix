package agent

// Phase playbooks: send each large methodology phase only while it is in use.
//
// The full 22-phase checklist is about two thirds of the root system prompt,
// and the system prompt is resent on every model call. Most of that text is
// per-phase guidance (injection payload ladders, IDOR procedures, recon
// steps) that only matters while the agent is working that phase.
//
// With XALGORIX_PHASE_PLAYBOOKS on, the root agent's system prompt keeps
// every phase heading, the checklist preamble, and every small or untriggered
// phase verbatim. The body of each large phase that plan tasks can trigger is
// replaced by a one-line note. Before each model call the engine appends the
// exact original text of every deferred phase that an active or next-ready
// plan task belongs to (phase 1 while there is no plan yet). The agent sees
// the same words as before for the work in front of it, not all 22 phases on
// every call.
//
// Delivery is decided from the live conversation, not from a "sent" flag: a
// playbook counts as present only while a message that starts with its marker
// is in the buffer. After a compaction, a hard context reset, or a restored
// checkpoint drops it, the next call adds it again if the phase is still in
// use.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/llm"
)

const (
	// minDeferredPhaseBytes keeps short phases inline: deferring a few hundred
	// bytes saves little and adds a delivery step.
	minDeferredPhaseBytes = 1500
	// maxDeferredPhase is the last phase that plan tasks can trigger. Phases
	// 20-22 (verification, novel discovery, report) have no task of their own,
	// so they always stay in the system prompt.
	maxDeferredPhase = 19
	// nextTasksForPlaybooks matches the lane-skill gate: the next three ready
	// tasks are the work the planner brief points the agent at.
	nextTasksForPlaybooks = 3
)

var phaseHeadingRE = regexp.MustCompile(`(?m)^### PHASE (\d+)\b[^\n]*`)

// phasePlaybookMarker starts every injected playbook message.
func phasePlaybookMarker(phase int) string {
	return fmt.Sprintf("[PHASE PLAYBOOK: PHASE %d]", phase)
}

// phasePlaybook is one deferred phase: its heading line, which stays in the
// system prompt, and its body, which is delivered on demand.
type phasePlaybook struct {
	Heading string
	Body    string
}

// deferPhasePlaybooks splits a checklist into the text that stays in the
// system prompt and the phases that are delivered on demand. Each deferred
// phase keeps its heading line in the prompt, followed by a note; its body
// (everything after the heading line, up to the next phase heading) is
// returned keyed by phase number. Substituting each body back for its note
// reproduces the input exactly.
func deferPhasePlaybooks(checklist string) (string, map[int]phasePlaybook) {
	locs := phaseHeadingRE.FindAllStringSubmatchIndex(checklist, -1)
	if len(locs) == 0 {
		return checklist, nil
	}
	var b strings.Builder
	bodies := make(map[int]phasePlaybook)
	b.WriteString(checklist[:locs[0][0]])
	for i, loc := range locs {
		end := len(checklist)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		heading := checklist[loc[0]:loc[1]]
		body := checklist[loc[1]:end]
		phase, err := strconv.Atoi(checklist[loc[2]:loc[3]])
		if err != nil || phase < 1 || phase > maxDeferredPhase || len(body) < minDeferredPhaseBytes {
			b.WriteString(heading)
			b.WriteString(body)
			continue
		}
		if _, dup := bodies[phase]; dup {
			b.WriteString(heading)
			b.WriteString(body)
			continue
		}
		bodies[phase] = phasePlaybook{Heading: heading, Body: body}
		b.WriteString(heading)
		b.WriteString(phasePlaybookNote(phase))
	}
	if len(bodies) == 0 {
		return checklist, nil
	}
	return b.String(), bodies
}

func phasePlaybookNote(phase int) string {
	return fmt.Sprintf("\n[The full Phase %d playbook is added to the conversation, marked %s, whenever Phase %d tasks are active or next in your plan. Follow it exactly as if it were written here.]\n\n", phase, phasePlaybookMarker(phase), phase)
}

// phasePlaybooksForPrompt applies deferral when the operator enabled it and
// this agent carries the full root checklist. It returns the checklist to put
// in the system prompt and the deferred bodies (nil when nothing is deferred).
func (a *Agent) phasePlaybooksForPrompt(checklist string) (string, map[int]phasePlaybook) {
	if a.cfg == nil || !a.cfg.PhasePlaybooks {
		return checklist, nil
	}
	return deferPhasePlaybooks(checklist)
}

// phasesInUse returns the phases whose playbooks the agent needs now: those
// of active tasks and of the next ready tasks, or phase 1 before a plan
// exists.
func phasesInUse(state *ScanState) []int {
	seen := map[int]bool{}
	if state == nil || state.Plan == nil || len(state.Plan.Tasks) == 0 {
		return []int{1}
	}
	for _, t := range state.Plan.Tasks {
		if t.Status == TaskActive {
			seen[t.Phase] = true
		}
	}
	for _, t := range state.Plan.NextTasks(nextTasksForPlaybooks) {
		seen[t.Phase] = true
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// injectPhasePlaybooks appends the playbook of every deferred phase now in use
// that is not already in the conversation. It returns the phases it added.
func (a *Agent) injectPhasePlaybooks() []int {
	if len(a.phasePlaybooks) == 0 {
		return nil
	}
	var added []int
	a.msgMu.Lock()
	defer a.msgMu.Unlock()
	if len(a.messages) == 0 || a.messages[0].Role != "system" {
		return nil
	}
	system := a.messages[0].Content
	for _, phase := range phasesInUse(a.state) {
		pb, ok := a.phasePlaybooks[phase]
		if !ok {
			continue
		}
		marker := phasePlaybookMarker(phase)
		// Deliver only what the live system prompt actually defers. A scan
		// resumed from a checkpoint saved without this setting still carries
		// the full phase text, and adding it again would only duplicate it.
		if !strings.Contains(system, phasePlaybookNote(phase)) {
			continue
		}
		present := false
		for i := range a.messages {
			if strings.HasPrefix(a.messages[i].Content, marker) {
				present = true
				break
			}
		}
		if present {
			continue
		}
		a.messages = append(a.messages, llm.Message{Role: "user", Content: marker + "\n" + pb.Heading + pb.Body})
		added = append(added, phase)
	}
	return added
}
