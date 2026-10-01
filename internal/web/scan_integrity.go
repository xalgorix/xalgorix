package web

import (
	"encoding/json"
	"log"
)

func knownPlanCounters(present bool, total, completed, skipped, unfinished int) (*int, *int, *int, *int) {
	if !present && total == 0 {
		return nil, nil, nil, nil
	}
	return &total, &completed, &skipped, &unfinished
}

// MarshalJSON preserves known zero counters and leaves legacy plans unknown.
func (r ScanRecord) MarshalJSON() ([]byte, error) {
	rec := r
	type wire ScanRecord
	total, completed, skipped, unfinished := knownPlanCounters(rec.PlanPresent, rec.PlanTasksTotal, rec.PlanTasksCompleted, rec.PlanTasksSkipped, rec.PlanTasksUnfinished)
	return json.Marshal(struct {
		*wire
		Total      *int `json:"plan_tasks_total,omitempty"`
		Completed  *int `json:"plan_tasks_completed,omitempty"`
		Skipped    *int `json:"plan_tasks_skipped,omitempty"`
		Unfinished *int `json:"plan_tasks_unfinished,omitempty"`
	}{(*wire)(&rec), total, completed, skipped, unfinished})
}

type scanInstanceWire ScanInstance

type instanceResponse struct {
	*scanInstanceWire
	InstanceID string     `json:"instance_id,omitempty"`
	Events     *[]WSEvent `json:"events,omitempty"`
	Total      *int       `json:"plan_tasks_total,omitempty"`
	Completed  *int       `json:"plan_tasks_completed,omitempty"`
	Skipped    *int       `json:"plan_tasks_skipped,omitempty"`
	Unfinished *int       `json:"plan_tasks_unfinished,omitempty"`
}

func instanceResponseLocked(inst *ScanInstance) instanceResponse {
	total, completed, skipped, unfinished := knownPlanCounters(inst.PlanPresent, inst.PlanTasksTotal, inst.PlanTasksCompleted, inst.PlanTasksSkipped, inst.PlanTasksUnfinished)
	return instanceResponse{scanInstanceWire: (*scanInstanceWire)(inst), Total: total, Completed: completed, Skipped: skipped, Unfinished: unfinished}
}

func (inst *ScanInstance) MarshalJSON() ([]byte, error) {
	return json.Marshal(instanceResponseLocked(inst))
}

func instanceAdmissionTime(inst *ScanInstance) string {
	if inst.AdmittedAt != "" {
		return inst.AdmittedAt
	}
	return inst.StartedAt
}

func applyRecordIntegrityLocked(inst *ScanInstance, rec *ScanRecord) {
	inst.Completion = rec.Completion
	inst.PlanPresent = rec.PlanPresent || rec.PlanTasksTotal > 0
	inst.PlanTasksTotal = rec.PlanTasksTotal
	inst.PlanTasksCompleted = rec.PlanTasksCompleted
	inst.PlanTasksSkipped = rec.PlanTasksSkipped
	inst.PlanTasksUnfinished = rec.PlanTasksUnfinished
}

func (s *Server) mirrorScanIntegrity(instanceID string, rec *ScanRecord) {
	if instanceID == "" || rec == nil || rec.ParentTarget != "" {
		return
	}
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()
	if inst := s.instances[instanceID]; inst != nil {
		inst.mu.Lock()
		applyRecordIntegrityLocked(inst, rec)
		// Child and discovery sessions do not own the coordinator's outcome.
		if rec.ScanMode != "wildcard" && rec.StopReason != "" && !isInterruptedInstanceStatus(inst.Status) {
			inst.StopReason = rec.StopReason
		}
		inst.mu.Unlock()
	}
}

func (s *Server) hydrateTerminalIntegrity(inst *ScanInstance) {
	inst.mu.RLock()
	id := inst.ID
	need := isTerminalScanStatus(inst.Status) && (inst.Completion == "" || !inst.PlanPresent || (inst.Completion == "partial" && inst.StopReason == ""))
	inst.mu.RUnlock()
	if !need {
		return
	}
	_, rec := s.findScanByInstanceID(id)
	if rec == nil || !isTerminalScanStatus(rec.Status) {
		return
	}
	s.reconcileTerminalStopReason(rec)
	inst.mu.Lock()
	recoveredReason := false
	if isTerminalScanStatus(inst.Status) {
		applyRecordIntegrityLocked(inst, rec)
		if inst.StopReason == "" && rec.StopReason != "" {
			inst.StopReason = rec.StopReason
			recoveredReason = true
		}
	}
	inst.mu.Unlock()
	if recoveredReason {
		if err := s.persistExactInstanceSnapshot(inst); err != nil {
			log.Printf("[checkpoint] terminal outcome reconciliation failed: %v", err)
		}
	}
}

// Reconcile missing terminal facts only when one physical root record proves
// the immutable instance identity. Multiple root records are ambiguous.
func (s *Server) reconcileTerminalStopReason(rec *ScanRecord) {
	if rec == nil || !isTerminalScanStatus(rec.Status) || rec.Completion != "partial" || rec.StopReason != "" || rec.ScanMode == "wildcard" {
		return
	}
	var owned *ScanRecord
	for _, entry := range s.findAllScanSummaries() {
		if entry.rec.InstanceID != rec.InstanceID || entry.rec.ParentTarget != "" {
			continue
		}
		if owned != nil {
			return
		}
		physical := entry.rec
		owned = &physical
	}
	if owned != nil && isTerminalScanStatus(owned.Status) && owned.Completion == "partial" {
		rec.StopReason = owned.StopReason
	}
}

func (s *Server) initializeSessionCounters(sess *scanSession) {
	_, _, tokens := sess.agent.LifetimeUsage()
	sess.lastSessionTokens = tokens
	sess.lastSessionProgress = sess.agent.AssessmentProgress()
	sess.record.TotalTokens = max(sess.record.TotalTokens, tokens)
	sess.record.AssessmentProgress = max(sess.record.AssessmentProgress, sess.lastSessionProgress)
	if sess.instanceID == "" {
		return
	}
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()
	if inst := s.instances[sess.instanceID]; inst != nil {
		inst.mu.Lock()
		if inst.UsageBySession == nil {
			inst.UsageBySession = make(map[string]sessionUsage)
		}
		if _, known := inst.UsageBySession[sess.id]; known {
			accountSessionUsageLocked(inst, sess.id, tokens, sess.lastSessionProgress)
		} else {
			// Legacy aggregate snapshots cannot attribute an already-spent delta
			// to one child. Seed its high-water mark without counting it twice.
			inst.UsageBySession[sess.id] = sessionUsage{tokens, sess.lastSessionProgress}
			if sess.parentTarget == "" && sess.scanMode != "wildcard" {
				inst.TotalTokens = max(inst.TotalTokens, tokens)
				inst.AssessmentProgress = max(inst.AssessmentProgress, sess.lastSessionProgress)
			}
		}
		inst.mu.Unlock()
	}
}

func cloneSessionUsage(usage map[string]sessionUsage) map[string]sessionUsage {
	if usage == nil {
		return nil
	}
	copy := make(map[string]sessionUsage, len(usage))
	for id, counters := range usage {
		copy[id] = counters
	}
	return copy
}

func mergeSessionUsage(previous, newer map[string]sessionUsage) map[string]sessionUsage {
	merged := cloneSessionUsage(previous)
	if merged == nil {
		merged = make(map[string]sessionUsage)
	}
	for id, counters := range newer {
		prior := merged[id]
		merged[id] = sessionUsage{max(prior.Tokens, counters.Tokens), max(prior.Progress, counters.Progress)}
	}
	return merged
}

func accountSessionUsageLocked(inst *ScanInstance, id string, tokens, progress int) {
	if inst.UsageBySession == nil {
		inst.UsageBySession = make(map[string]sessionUsage)
	}
	previous := inst.UsageBySession[id]
	if tokens > previous.Tokens {
		inst.TotalTokens += tokens - previous.Tokens
		previous.Tokens = tokens
	}
	if progress > previous.Progress {
		inst.AssessmentProgress += progress - previous.Progress
		previous.Progress = progress
	}
	inst.UsageBySession[id] = previous
}

func (s *Server) syncSessionAdmissionClocks(sess *scanSession) {
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()
	if inst := s.instances[sess.instanceID]; inst != nil {
		inst.mu.RLock()
		sess.record.AdmittedAt, sess.record.ResumedAt = inst.AdmittedAt, inst.ResumedAt
		if sess.parentTarget == "" && sess.scanMode != "wildcard" && inst.StartedAt != "" {
			sess.record.StartedAt = inst.StartedAt
		}
		inst.mu.RUnlock()
	}
}
