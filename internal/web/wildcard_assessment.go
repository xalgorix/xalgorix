package web

import (
	"encoding/json"
	"strings"
)

// MarshalJSON retains known zero dispositions without inventing legacy plans.
func (summary SubScanSummary) MarshalJSON() ([]byte, error) {
	type wire SubScanSummary
	total, completed, skipped, unfinished := knownPlanCounters(summary.PlanPresent, summary.PlanTasksTotal, summary.PlanTasksCompleted, summary.PlanTasksSkipped, summary.PlanTasksUnfinished)
	return json.Marshal(struct {
		*wire
		Total      *int `json:"plan_tasks_total,omitempty"`
		Completed  *int `json:"plan_tasks_completed,omitempty"`
		Skipped    *int `json:"plan_tasks_skipped,omitempty"`
		Unfinished *int `json:"plan_tasks_unfinished,omitempty"`
	}{(*wire)(&summary), total, completed, skipped, unfinished})
}

func cloneSubScanSummary(summary *SubScanSummary) *SubScanSummary {
	if summary == nil {
		return nil
	}
	copySummary := *summary
	return &copySummary
}

func subScanSummaryFromRecord(rec *ScanRecord) SubScanSummary {
	return SubScanSummary{
		ID: rec.ID, Target: rec.Target, StartedAt: rec.StartedAt, FinishedAt: rec.FinishedAt,
		Status: rec.Status, VulnCount: len(rec.Vulns), TotalTokens: rec.TotalTokens,
		Completion: rec.Completion, StopReason: rec.StopReason,
		PlanPresent: rec.PlanPresent, PlanTasksTotal: rec.PlanTasksTotal,
		PlanTasksCompleted: rec.PlanTasksCompleted, PlanTasksSkipped: rec.PlanTasksSkipped,
		PlanTasksUnfinished: rec.PlanTasksUnfinished,
	}
}

func isWildcardAssessmentParent(rec *ScanRecord) bool {
	return rec != nil && rec.ParentTarget == "" &&
		(rec.ScanMode == "wildcard" || rec.SubScanTotal > 0 || len(rec.SubScans) > 0)
}

func knownSubScanPlan(child SubScanSummary) bool {
	return (child.PlanPresent || child.PlanTasksTotal > 0) && child.PlanTasksTotal >= 0 &&
		child.PlanTasksCompleted >= 0 && child.PlanTasksSkipped >= 0 && child.PlanTasksUnfinished >= 0 &&
		child.PlanTasksTotal == child.PlanTasksCompleted+child.PlanTasksSkipped+child.PlanTasksUnfinished
}

func isWildcardAssessmentReason(reason string) bool {
	switch reason {
	case "wildcard_assessment_incomplete", "wildcard_assessment_unknown", "wildcard_discovery_incomplete", "wildcard_resource_limit":
		return true
	}
	return false
}

// Aggregate only physical assessment outcomes. Lifecycle dispositions count
// terminated children, including partial assessments, and remain independent.
// Aggregate plan counters are known only when every inventory child has a
// valid saved plan; individual known plans remain available on the children.
func aggregateWildcardAssessment(rec *ScanRecord) {
	if !isWildcardAssessmentParent(rec) {
		return
	}
	allPlans := len(rec.SubScans) > 0 && rec.SubScanTotal <= len(rec.SubScans)
	allFull := allPlans && rec.SubScanSkipped == 0 && isCompletedScanStatus(rec.Status)
	unknown := len(rec.SubScans) == 0 || rec.SubScanTotal > len(rec.SubScans)
	incomplete := !isCompletedScanStatus(rec.Status)
	total, completed, skipped, unfinished := 0, 0, 0, 0
	seenIDs := make(map[string]bool)
	for _, child := range rec.SubScans {
		knownPlan := knownSubScanPlan(child)
		planClaimed := child.PlanPresent || child.PlanTasksTotal != 0 || child.PlanTasksCompleted != 0 || child.PlanTasksSkipped != 0 || child.PlanTasksUnfinished != 0
		allPlans = allPlans && knownPlan
		duplicate := child.ID != "" && seenIDs[child.ID]
		seenIDs[child.ID] = true
		allPlans = allPlans && !duplicate
		if knownPlan {
			total += child.PlanTasksTotal
			completed += child.PlanTasksCompleted
			skipped += child.PlanTasksSkipped
			unfinished += child.PlanTasksUnfinished
		}
		full := child.ID != "" && isCompletedScanStatus(child.Status) && child.Completion == "full" &&
			(!planClaimed || (knownPlan && child.PlanTasksUnfinished == 0))
		allFull = allFull && full && !duplicate
		unknown = unknown || duplicate
		unknown = unknown || child.ID == "" || (child.Completion != "full" && child.Completion != "partial")
		unknown = unknown || (planClaimed && !knownPlan)
		incomplete = incomplete || child.Completion == "partial" || !isCompletedScanStatus(child.Status) ||
			(knownPlan && child.PlanTasksUnfinished > 0)
	}
	rec.PlanPresent = allPlans
	rec.PlanTasksTotal, rec.PlanTasksCompleted, rec.PlanTasksSkipped, rec.PlanTasksUnfinished = 0, 0, 0, 0
	if allPlans {
		rec.PlanTasksTotal, rec.PlanTasksCompleted, rec.PlanTasksSkipped, rec.PlanTasksUnfinished = total, completed, skipped, unfinished
	}
	// Running/resumed parents cannot inherit enumeration's terminal outcome.
	if !isTerminalScanStatus(rec.Status) {
		rec.Completion = ""
		if isWildcardAssessmentReason(rec.StopReason) {
			rec.StopReason = ""
		}
		return
	}
	discoveryFull := rec.Discovery != nil && isCompletedScanStatus(rec.Discovery.Status) && rec.Discovery.Completion == "full"
	if rec.Discovery != nil && (rec.Discovery.PlanPresent || rec.Discovery.PlanTasksTotal > 0) {
		discoveryFull = discoveryFull && knownSubScanPlan(*rec.Discovery) && rec.Discovery.PlanTasksUnfinished == 0
	}
	allFull = allFull && discoveryFull && !unknown
	rec.Completion = "partial"
	reason := "wildcard_assessment_unknown"
	switch {
	case rec.SubScanSkipped > 0:
		reason = "wildcard_resource_limit"
	case incomplete:
		reason = "wildcard_assessment_incomplete"
	case rec.Discovery != nil && !discoveryFull:
		reason = "wildcard_discovery_incomplete"
	case allFull:
		rec.Completion = "full"
		reason = ""
	}
	// A completed parent can retain the recovery placeholder from an older
	// snapshot. It no longer describes an interruption once work has finished.
	// Keep the marker on recoverable stopped/pending records and preserve
	// explicit coordinator cancellation/failure reasons.
	staleResume := isCompletedScanStatus(rec.Status) && rec.StopReason == "server_restart_resuming"
	if rec.StopReason == "" || isWildcardAssessmentReason(rec.StopReason) || staleResume {
		rec.StopReason = reason
	}
}

// Refresh only exact inventory child identities. Resume and finalization use
// the events-free record cache, never the coordinator snapshot shared by the
// children. A missing physical record leaves its saved assessment unchanged.
func (s *Server) refreshWildcardAssessmentChildren(rec *ScanRecord) {
	if !isWildcardAssessmentParent(rec) || len(rec.SubScans) == 0 {
		return
	}
	byID := make(map[string]ScanRecord)
	for _, entry := range s.findAllScanSummaries() {
		if isChildOfScan(rec, &entry.rec) {
			byID[entry.rec.ID] = entry.rec
		}
	}
	for i, child := range rec.SubScans {
		if physical, ok := byID[child.ID]; ok && normalizeScanTarget(physical.Target) == normalizeScanTarget(child.Target) {
			rec.SubScans[i] = subScanSummaryFromRecord(&physical)
		}
	}
}

func aggregateWildcardInstanceLocked(inst *ScanInstance) {
	rec := &ScanRecord{
		ScanMode: inst.ScanMode, ParentTarget: inst.ParentTarget, Status: inst.Status, StopReason: inst.StopReason,
		SubScans: inst.SubScans, SubScanTotal: inst.SubScanTotal, SubScanSkipped: inst.SubScanSkipped, Discovery: inst.Discovery,
	}
	aggregateWildcardAssessment(rec)
	applyRecordIntegrityLocked(inst, rec)
	inst.StopReason = rec.StopReason
	inst.wildcardAssessmentReady = true
}

// Keep the consumed prefix and any physical child when a resumed run applies
// a smaller resource cap. This preserves both resume indexing and evidence.
func capWildcardInventory(inventory []string, limit, consumed int, wt wildcardTarget, existing []SubScanSummary) ([]string, int) {
	if limit <= 0 || len(inventory) <= limit {
		return inventory, 0
	}
	started := make(map[string]bool)
	for _, child := range existing {
		if child.ID != "" || child.StartedAt != "" {
			started[strings.TrimSpace(child.Target)] = true
		}
	}
	kept := make([]string, 0, len(inventory))
	for i, target := range inventory {
		if i < limit || i < consumed || isMandatoryWildcardEntry(target, wt) || started[strings.TrimSpace(target)] {
			kept = append(kept, target)
		}
	}
	return kept, len(inventory) - len(kept)
}
