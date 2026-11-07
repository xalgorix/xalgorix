package agent

// coverage_epoch.go implements OPTIONAL epoch-based coverage convergence
// (XALGORIX_EPOCH_COVERAGE, default on). It is inert when the flag is off.
//
// Problem it solves
// -----------------
// taskCoverageComplete measures per-endpoint class completion against
// state.DiscoveredEndpoints, which GROWS while the scan runs (active recon
// keeps finding endpoints). Every new endpoint adds an obligation to every
// applicable class task, so the completion bar recedes as fast as the agent
// covers it: class tasks never close, their phases stay "plan tasks pending",
// the finish gate never opens, and the scan runs until a watchdog kills it
// mid-coverage — never reaching a clean "completed" terminal state (so the
// completion webhook never fires). On large/growing surfaces this means scans
// effectively never finish.
//
// The fix: bounded coverage epochs
// --------------------------------
//   - Epoch N tests a FROZEN snapshot (CoverageBaseline) of the surface.
//     taskCoverageComplete measures against that snapshot, so its tasks can
//     actually reach "completed".
//   - Endpoints discovered DURING epoch N still accumulate in
//     DiscoveredEndpoints, but are NOT in the denominator, so they cannot
//     reopen epoch-N tasks.
//   - When epoch N's testable obligations are all met AND new surface exists,
//     advanceCoverageEpoch folds the full DiscoveredEndpoints set into the
//     next baseline (epoch N+1) and REOPENS the class tasks the new endpoints
//     leave uncovered (reconcilePlan only upgrades pending→completed, never the
//     reverse, so the reopen is explicit here).
//   - When an epoch's obligations are met with NO new surface, the scan has
//     converged: the baseline equals the full discovered surface and every
//     applicable (endpoint × class) pair is covered — identical coverage to the
//     legacy path, but terminating.
//
// No-compromise guarantee
// -----------------------
// Every discovered endpoint is eventually folded into a baseline (on advance)
// and therefore tested for every applicable class before the finish gate can
// open: finish requires all tasks complete, which requires the current
// baseline fully covered, and the epoch only stops advancing once the baseline
// equals the entire discovered surface. Epochs change WHEN completion is
// measured, never WHAT must be tested. With the flag off every function here is
// a no-op and the legacy live-denominator behavior is byte-for-byte intact.

// epochActive reports whether epoch-based coverage is enabled for this scan.
func epochActive(state *ScanState) bool {
	return state != nil && state.EpochCoverage
}

// coverageDenominator returns the endpoint set that per-endpoint coverage
// predicates measure against: the frozen epoch baseline when epochs are active
// and started, else the live discovered set (legacy behavior).
func coverageDenominator(state *ScanState) []string {
	if epochActive(state) && state.CoverageEpoch > 0 {
		return state.CoverageBaseline
	}
	return state.DiscoveredEndpoints
}

// ensureCoverageEpoch opens epoch 1 the first time there is surface to freeze.
// No-op when epochs are disabled or an epoch is already open. Called at the top
// of reconcilePlan so every coverage evaluation sees a stable denominator.
func ensureCoverageEpoch(state *ScanState) {
	if !epochActive(state) || state.CoverageEpoch > 0 {
		return
	}
	if len(state.DiscoveredEndpoints) == 0 {
		return
	}
	state.CoverageEpoch = 1
	state.CoverageBaseline = append([]string(nil), state.DiscoveredEndpoints...)
}

// epochObligationsMet reports whether the current epoch's testable plan
// obligations are all settled — i.e. no task is still pending or active. This
// mirrors the finish gate's plan criterion (completion.go), so an epoch
// advances (or the scan converges) exactly at the point the scan would
// otherwise try to finish.
func epochObligationsMet(state *ScanState) bool {
	if state == nil || state.Plan == nil {
		return false
	}
	for _, t := range state.Plan.Tasks {
		if t.Status == TaskPending || t.Status == TaskActive {
			return false
		}
	}
	return true
}

// taskIsMeasurable reports whether a task has a completion path the engine can
// evaluate — a vuln class (per-endpoint or whole-target coverage) or one of the
// structured engine tasks (recon, dirbust, auth-session) — as opposed to a
// class-less exploratory hypothesis the coverage matrix cannot reconcile.
func taskIsMeasurable(t *Task) bool {
	if t == nil {
		return false
	}
	if t.VulnClass != "" {
		return true
	}
	switch t.ID {
	case "recon", "dirbust", "auth-session":
		return true
	}
	return false
}

// reconcilableExploratoryTask reports whether a still-open task is a class-less
// exploratory hypothesis the convergence reconcile may close.
func reconcilableExploratoryTask(t *Task) bool {
	return t != nil && !taskIsMeasurable(t)
}

// measurableObligationsMet reports whether every MEASURABLE task is terminal, so
// the only work still open is class-less exploratory tasks. It returns false for
// a plan with no measurable task at all, so a degenerate plan never
// auto-converges. Distinct from epochObligationsMet (which requires zero pending
// tasks): the whole point here is that class-less tasks are still pending and
// cannot be closed by any coverage predicate.
func measurableObligationsMet(state *ScanState) bool {
	if state == nil || state.Plan == nil {
		return false
	}
	sawMeasurable := false
	for _, t := range state.Plan.Tasks {
		if !taskIsMeasurable(t) {
			continue
		}
		sawMeasurable = true
		if t.Status == TaskPending || t.Status == TaskActive {
			return false
		}
	}
	return sawMeasurable
}

// surfaceBeyondBaseline reports whether DiscoveredEndpoints contains any
// endpoint not in the current frozen baseline — i.e. new surface appeared since
// the epoch was frozen and still owes coverage.
func surfaceBeyondBaseline(state *ScanState) bool {
	if state == nil {
		return false
	}
	base := make(map[string]bool, len(state.CoverageBaseline))
	for _, e := range state.CoverageBaseline {
		base[e] = true
	}
	for _, e := range state.DiscoveredEndpoints {
		if !base[e] {
			return true
		}
	}
	return false
}

// advanceCoverageEpoch rolls the epoch forward when the current baseline's
// obligations are met but new surface has appeared since it was frozen. It
// folds the full discovered surface into the next baseline and reopens the
// per-endpoint class tasks the enlarged baseline leaves uncovered, so the new
// endpoints are actually tested. Returns true when it opened a new epoch.
//
// When obligations are met and NO new surface exists, the scan has converged
// and this is a no-op — the finish gate may now open with the entire surface
// covered.
func advanceCoverageEpoch(state *ScanState) bool {
	if !epochActive(state) || state.CoverageEpoch == 0 {
		return false
	}
	if !epochObligationsMet(state) || !surfaceBeyondBaseline(state) {
		return false
	}
	state.CoverageBaseline = append([]string(nil), state.DiscoveredEndpoints...)
	state.CoverageEpoch++
	if state.Plan != nil {
		for _, t := range state.Plan.Tasks {
			if t.Status != TaskCompleted {
				continue
			}
			// Whole-target and specific-endpoint tasks are scan-level or
			// single-endpoint: the enlarged baseline cannot leave them
			// uncovered, so they stay settled. Only generic per-endpoint class
			// tasks can owe the new endpoints.
			if t.WholeTarget || t.VulnClass == "" {
				continue
			}
			if !taskCoverageComplete(state, t) {
				t.Status = TaskPending
			}
		}
	}
	return true
}
