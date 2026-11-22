// Package agent — plan_carryover.go keeps settled task progress across a
// build_plan rebuild.
//
// build_plan constructs a brand-new plan with every task pending. Models call
// it more than once per scan (observed: three rebuilds about two hours apart),
// and each rebuild used to reset the plan's progress to zero, so the model
// re-worked or re-marked tasks it had already finished. refreshEnginePlan
// already preserves settled outcomes for engine rebuilds; this is the
// equivalent for the model's rebuild.
//
// A status carries over only when it is safe to:
//   - The new task is the SAME task: same id, origin, canonical vuln class and
//     endpoint scope. A reused id with a different class or endpoint starts
//     pending.
//   - Only completed and skipped statuses carry, and only onto the same status.
//     A task that was not completed before is never completed by a rebuild.
//   - Every carried status is re-checked with the same guards update_plan
//     applies (planCompletionRejection / planSkipRejection) against the current
//     state. A carried status is therefore never one the model could not set
//     by hand right after the rebuild. Engine coverage tasks (Origin "auto")
//     still close only on engine-verified coverage.
//   - Skips also have to survive skipDispositionStillValid, the check the
//     engine's own plan refresh uses, so a not_applicable judgment the current
//     surface contradicts is reopened.
//   - Engine-only closures (blocked_no_progress, untested_at_finish,
//     coverage_sufficient, coverage_complete) and untyped legacy skips never
//     carry: they record work that was NOT done, and a rebuild has always
//     reopened them.
package agent

import (
	"fmt"
	"strings"
)

// planCarryOver records what a build_plan rebuild kept from the plan it
// replaced. Each list holds task ids in the old plan's order.
type planCarryOver struct {
	Completed []string // completed status kept
	Skipped   []string // skipped status (typed disposition) kept
	Reopened  []string // settled before, present in the new plan, now pending
	Dropped   []string // settled before, absent from the new plan
}

func (c planCarryOver) kept() int { return len(c.Completed) + len(c.Skipped) }

// hadSettled reports whether the replaced plan had any settled task, which is
// when the model needs to hear what happened to its progress.
func (c planCarryOver) hadSettled() bool {
	return c.kept()+len(c.Reopened)+len(c.Dropped) > 0
}

// summary is the model-facing report appended to the build_plan result.
func (c planCarryOver) summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Progress kept: %d task(s) from the previous plan keep their status (%d completed, %d skipped) because their id, vuln_class and endpoint are unchanged and the current evidence still supports them.\n",
		c.kept(), len(c.Completed), len(c.Skipped)))
	if len(c.Reopened) > 0 {
		sb.WriteString(fmt.Sprintf("Reopened as pending (%d): %s. Their scope changed (vuln_class, endpoint, or a model task replaced by an engine coverage task), or the current surface and coverage evidence no longer support the old status.\n",
			len(c.Reopened), truncList(c.Reopened, 8)))
	}
	if len(c.Dropped) > 0 {
		sb.WriteString(fmt.Sprintf("Settled before but not in the new plan (%d): %s.\n", len(c.Dropped), truncList(c.Dropped, 8)))
	}
	sb.WriteString("Record progress with update_plan. Rebuild only to add a missed vuln class or endpoint, and keep existing task ids, vuln_class and endpoint so their status carries over.\n")
	return sb.String()
}

// carryOverPlanProgress copies completed and skipped statuses from prev onto
// the matching pending tasks of next, under the rules in the file comment.
// next must already be the plan the state will use, with the state's surface
// updated, so the guards see what the engine sees.
func carryOverPlanProgress(state *ScanState, prev, next *Plan) planCarryOver {
	var out planCarryOver
	if state == nil || prev == nil || next == nil {
		return out
	}
	for _, old := range prev.Tasks {
		if old.Status != TaskCompleted && old.Status != TaskSkipped {
			continue
		}
		nt := next.Get(old.ID)
		if nt == nil {
			out.Dropped = append(out.Dropped, old.ID)
			continue
		}
		if nt.Status != TaskPending || !samePlanTask(old, nt) || !carryTaskStatus(state, old, nt) {
			out.Reopened = append(out.Reopened, old.ID)
			continue
		}
		if nt.Status == TaskCompleted {
			out.Completed = append(out.Completed, old.ID)
		} else {
			out.Skipped = append(out.Skipped, old.ID)
		}
	}
	return out
}

// samePlanTask reports whether nt is the same unit of work as old: same id,
// origin, canonical vuln class, endpoint scope and completion semantics.
func samePlanTask(old, nt *Task) bool {
	return old.ID == nt.ID &&
		old.Origin == nt.Origin &&
		old.WholeTarget == nt.WholeTarget &&
		old.Prerequisite == nt.Prerequisite &&
		planTaskClassKey(old.VulnClass) == planTaskClassKey(nt.VulnClass) &&
		planTaskScopeKey(old) == planTaskScopeKey(nt)
}

// planTaskClassKey canonicalizes a task's vuln class. Unknown classes compare
// by their trimmed, lowercased name so two different unknown classes never
// match.
func planTaskClassKey(class string) string {
	if c := normalizeCoverageClass(class); c != "" {
		return c
	}
	return strings.ToLower(strings.TrimSpace(class))
}

// planTaskScopeKey is the endpoint scope a task's completion is measured on.
// Engine tasks are scoped to their class across the whole coverage
// denominator; their Endpoint field is only a display sample of the surface
// that changes as the surface grows (see newCoverageTask and
// taskCoverageComplete), so it is not part of their identity. Model tasks are
// scoped to the endpoint they name.
func planTaskScopeKey(t *Task) string {
	if t.Origin == "auto" {
		return ""
	}
	return normalizePlanEndpoint(t.Endpoint)
}

// normalizePlanEndpoint makes trivially different spellings of one endpoint
// compare equal (surrounding whitespace, trailing slash, query string, host
// case). Host-qualified and bare paths stay distinct, and a free-form list of
// endpoints is compared verbatim after collapsing whitespace.
func normalizePlanEndpoint(endpoint string) string {
	endpoint = strings.Join(strings.Fields(endpoint), " ")
	if endpoint == "" || strings.ContainsAny(endpoint, " ,") {
		return endpoint
	}
	if aliases := endpointCoverageAliases(endpoint); len(aliases) > 0 {
		return aliases[0]
	}
	return endpoint
}

// carryTaskStatus applies old's settled status to nt when today's guards
// accept it, and reports whether it did. nt is left untouched on rejection.
func carryTaskStatus(state *ScanState, old, nt *Task) bool {
	switch old.Status {
	case TaskCompleted:
		// The old notes hold whatever completion evidence the original
		// transition was accepted on.
		if planCompletionRejection(state, nt, old.Notes) != "" {
			return false
		}
		nt.Status = TaskCompleted
		nt.Notes = carriedPlanNotes(old, nt)
		return true
	case TaskSkipped:
		if !modelSettableDisposition(old.Disposition) {
			return false
		}
		candidate := *nt
		candidate.Status = TaskSkipped
		candidate.Disposition = old.Disposition
		candidate.DispositionSurface = old.DispositionSurface
		if !skipDispositionStillValid(state, &candidate) {
			return false
		}
		if planSkipRejection(state, &candidate, old.Disposition, old.Notes) != "" {
			return false
		}
		candidate.Notes = carriedPlanNotes(old, nt)
		*nt = candidate
		return true
	}
	return false
}

// modelSettableDisposition reports whether d is one of the typed dispositions
// update_plan accepts. Engine-only closures and untyped legacy skips are
// excluded on purpose: they mark work that was not done.
func modelSettableDisposition(d string) bool {
	switch d {
	case DispositionNotApplicable, DispositionBlockedMissingAuth, DispositionBlockedMissingSecondID,
		DispositionBlockedUnreachable, DispositionBlockedPolicy, DispositionExhausted, DispositionSuperseded:
		return true
	}
	return false
}

// carriedPlanNotes keeps the old task's notes (they hold the rationale and
// evidence the status was accepted on). An engine task's notes are engine
// text, so the old record wins outright; a model task also keeps any new note
// the model wrote for it in the rebuild.
func carriedPlanNotes(old, nt *Task) string {
	oldNotes := strings.TrimSpace(old.Notes)
	newNotes := strings.TrimSpace(nt.Notes)
	switch {
	case nt.Origin == "auto" || newNotes == "" || strings.Contains(oldNotes, newNotes):
		if oldNotes == "" {
			return newNotes
		}
		return oldNotes
	case oldNotes == "":
		return newNotes
	default:
		return oldNotes + " | " + newNotes
	}
}

// planTaskStatusLabel renders a task status for the model, with its typed
// disposition when it has one.
func planTaskStatusLabel(t *Task) string {
	if t.Status == TaskSkipped && t.Disposition != "" {
		return string(t.Status) + ": " + t.Disposition
	}
	return string(t.Status)
}
