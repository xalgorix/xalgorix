package agent

type assessmentSnapshot struct {
	PlanPresent                           bool
	Total, Completed, Skipped, Unfinished int
	WorkedPhases                          []int
	Phases                                map[int]PhaseDisposition
	Completion                            string
}

// publishAssessmentSnapshot runs at owner-loop safe points. Web consumers
// read immutable snapshots instead of racing with in-flight plan mutations.
func (a *Agent) publishAssessmentSnapshot() {
	if a.state == nil {
		return
	}
	snapshot := &assessmentSnapshot{Completion: a.state.CompletionStatus, Phases: ComputePhaseDispositions(a.state)}
	if plan := a.state.Plan; plan != nil {
		snapshot.PlanPresent = true
		snapshot.Total = len(plan.Tasks)
		pending, active, completed, skipped := plan.Counts()
		snapshot.Completed, snapshot.Skipped, snapshot.Unfinished = completed, skipped, pending+active
		seen := map[int]bool{}
		for _, task := range plan.Tasks {
			if task.Status == TaskCompleted && task.Phase > 0 && !seen[task.Phase] {
				seen[task.Phase] = true
				snapshot.WorkedPhases = append(snapshot.WorkedPhases, task.Phase)
			}
		}
	}
	a.publishedAssessment.Store(snapshot)
}

func (a *Agent) HasPlan() bool {
	if a == nil {
		return false
	}
	if snapshot := a.publishedAssessment.Load(); snapshot != nil {
		return snapshot.PlanPresent
	}
	return a.state != nil && a.state.Plan != nil
}
