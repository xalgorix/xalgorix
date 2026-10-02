package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var errDispatchSnapshotNotFound = errors.New("dispatch snapshot not found")

func (s *Server) dispatchSnapshotPath(instanceID string) string {
	return filepath.Join(s.dataDir, ".dispatches", instanceID+".json")
}

func (s *Server) loadExactDispatchSnapshot(instanceID string) (*ScanRecord, error) {
	instanceID = strings.TrimSpace(instanceID)
	if !validDispatchID(instanceID) {
		return nil, errDispatchSnapshotNotFound
	}
	data, err := os.ReadFile(s.dispatchSnapshotPath(instanceID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errDispatchSnapshotNotFound
	}
	if err != nil {
		return nil, err
	}
	var rec ScanRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	if rec.InstanceID != instanceID || rec.ID != instanceID {
		return nil, fmt.Errorf("dispatch snapshot identity mismatch for %q", instanceID)
	}
	return &rec, nil
}

func (s *Server) saveExactDispatchSnapshot(rec *ScanRecord) error {
	if rec == nil || !validDispatchID(strings.TrimSpace(rec.InstanceID)) || rec.ID != rec.InstanceID {
		return errors.New("invalid exact dispatch snapshot")
	}
	// Webhook URLs are credentials. Exact coordinator snapshots carry status,
	// findings, events, and dispatch evidence only; they never duplicate secrets.
	copyRec := *rec
	copyRec.DiscordWebhook = ""
	copyRec.DiscordWebhookConfigured = rec.DiscordWebhookConfigured
	copyRec.Events = append([]WSEvent(nil), rec.Events...)
	copyRec.Vulns = append([]VulnSummary(nil), rec.Vulns...)
	copyRec.SubScans = cloneSubScanSummaries(rec.SubScans)
	copyRec.Discovery = cloneSubScanSummary(rec.Discovery)

	data, err := json.MarshalIndent(&copyRec, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.dispatchSnapshotPath(rec.InstanceID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".dispatch-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if removeErr := os.Remove(tmpPath); removeErr != nil && !os.IsNotExist(removeErr) {
			// The rename normally removes tmpPath. A leftover is non-fatal but
			// should remain diagnosable instead of being silently ignored.
			fmt.Fprintf(os.Stderr, "warning: remove dispatch temp file %s: %v\n", tmpPath, removeErr)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.dispatchSnapshotPath(rec.InstanceID)); err != nil {
		return err
	}
	if err := fsyncParentDir(s.dispatchSnapshotPath(rec.InstanceID)); err != nil {
		return fmt.Errorf("commit exact dispatch snapshot rename: %w", err)
	}
	return nil
}

// persistPendingDispatchSnapshot makes HTTP acceptance durable before the scan
// goroutine can register. A prior exact-stop tombstone always wins.
func (s *Server) persistPendingDispatchSnapshot(req ScanRequest, instanceID string) (string, bool, error) {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	if existing, err := s.loadExactDispatchSnapshot(instanceID); err == nil {
		delete(s.dispatchReservations, instanceID)
		return existing.Status, false, nil
	} else if !errors.Is(err, errDispatchSnapshotNotFound) {
		delete(s.dispatchReservations, instanceID)
		return "", false, err
	}
	now := time.Now().Format(time.RFC3339Nano)
	rec := &ScanRecord{
		ID: instanceID, InstanceID: instanceID, Name: req.Name,
		Target: strings.Join(req.Targets, ", "), StartedAt: now,
		Status: "pending", ScanMode: req.ScanMode, Instruction: req.Instruction,
		SeverityFilter:           append([]string(nil), req.SeverityFilter...),
		DiscordWebhookConfigured: req.DiscordWebhook != "" || s.discordWebhook != "",
		ReconMode:                req.ReconMode, ScanIntensity: req.ScanIntensity,
		Events: []WSEvent{}, Vulns: []VulnSummary{}, SubScans: []SubScanSummary{},
		CompanyName: req.CompanyName, LogoPath: req.LogoPath,
		Phases: append([]int(nil), req.Phases...), CurrentPhase: firstSelectedPhase(req.Phases),
	}
	if err := s.saveExactDispatchSnapshot(rec); err != nil {
		delete(s.dispatchReservations, instanceID)
		return "", false, err
	}
	return "pending", true, nil
}

// persistExactInstanceSnapshot serializes the in-memory snapshot with exact
// cancellation. Taking dispatchMu before reading the instance prevents a stale
// running copy captured before stop from overwriting a durable tombstone.
func (s *Server) persistExactInstanceSnapshot(inst *ScanInstance) error {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	return s.persistExactInstanceSnapshotLocked(inst)
}

// persistExactInstanceSnapshotLocked persists one coherent instance snapshot.
// The caller must hold dispatchMu; the lock order is dispatchMu -> instance.mu.
func (s *Server) persistExactInstanceSnapshotLocked(inst *ScanInstance) error {
	rec := s.scanRecordFromInstance(inst)
	if rec == nil {
		return errors.New("missing exact instance")
	}
	return s.saveExactDispatchSnapshot(rec)
}

// retryReadyExactSnapshot lets an authoritative GET complete a terminal
// snapshot whose background persistence exhausted its transient retries.
func (s *Server) retryReadyExactSnapshot(inst *ScanInstance) error {
	if inst == nil {
		return errors.New("missing exact instance")
	}
	inst.mu.RLock()
	ready := inst.snapshotReady && inst.snapshotFinalizing && isTerminalScanStatus(inst.Status)
	inst.mu.RUnlock()
	if !ready {
		return errors.New("exact instance snapshot is not ready")
	}
	if err := s.persistExactInstanceSnapshot(inst); err != nil {
		return err
	}
	inst.mu.Lock()
	if inst.snapshotReady && isTerminalScanStatus(inst.Status) {
		inst.snapshotFinalizing = false
	}
	status, stopReason := inst.Status, inst.StopReason
	inst.mu.Unlock()
	if !shouldPreserveQueueStateOnExit(status, stopReason, false) {
		if err := s.clearQueueStateDurable(inst.ID); err != nil {
			// The terminal tombstone is already durable and prevents resurrection;
			// retain visibility while making deletion durability diagnosable.
			fmt.Fprintf(os.Stderr, "warning: exact snapshot durable but queue cleanup failed for %s: %v\n", inst.ID, err)
		}
	}
	return nil
}

// abortPendingDispatchSnapshot records a concrete local rejection when HTTP
// acceptance cannot also persist a resumable queue request. A retry therefore
// sees a terminal rejection instead of an orphaned pending acknowledgement.
func (s *Server) abortPendingDispatchSnapshot(instanceID, reason string) error {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	rec, err := s.loadExactDispatchSnapshot(instanceID)
	if err != nil {
		return err
	}
	if !isTerminalScanStatus(rec.Status) {
		rec.Status = "failed"
		rec.StopReason = reason
		rec.FinishedAt = time.Now().Format(time.RFC3339Nano)
		normalizeTerminalWildcardProgress(rec)
	}
	delete(s.dispatchReservations, instanceID)
	return s.saveExactDispatchSnapshot(rec)
}

const exactStopEventContent = "Instance stopped by user"

func exactStopEvent(instanceID string) WSEvent {
	return withEventTimestamp(WSEvent{
		Type:       "stopped",
		Content:    exactStopEventContent,
		InstanceID: instanceID,
	})
}

func ensureExactStopEvent(events *[]WSEvent, instanceID string) bool {
	for i := range *events {
		if (*events)[i].Type == "stopped" && (*events)[i].Content == exactStopEventContent {
			if (*events)[i].InstanceID == "" {
				(*events)[i].InstanceID = instanceID
			}
			return false
		}
	}
	*events = append(*events, exactStopEvent(instanceID))
	return true
}

func instanceHasExactStopEvent(inst *ScanInstance) bool {
	if inst == nil {
		return false
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	for _, event := range inst.events {
		if event.Type == "stopped" && event.Content == exactStopEventContent {
			return true
		}
	}
	return false
}

func serverInstanceHasExactStopEvent(s *Server, instanceID string) bool {
	s.instancesMu.RLock()
	inst := s.instances[instanceID]
	s.instancesMu.RUnlock()
	return instanceHasExactStopEvent(inst)
}

func stableEventKey(event WSEvent) string {
	data, _ := json.Marshal(event)
	return string(data)
}

func stableDedupeAndSortEvents(groups ...[]WSEvent) []WSEvent {
	seen := make(map[string]struct{})
	var events []WSEvent
	for _, group := range groups {
		for _, event := range group {
			key := stableEventKey(event)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			events = append(events, event)
		}
	}
	sort.SliceStable(events, func(i, j int) bool {
		left, right := events[i].Timestamp, events[j].Timestamp
		if left != right {
			if left == "" {
				return false
			}
			if right == "" {
				return true
			}
			return left < right
		}
		return stableEventKey(events[i]) < stableEventKey(events[j])
	})
	return events
}

func mergeDispatchSubScan(children *[]SubScanSummary, candidate SubScanSummary) {
	for i := range *children {
		if ((*children)[i].ID != "" && (*children)[i].ID == candidate.ID) ||
			(normalizeScanTarget((*children)[i].Target) != "" && normalizeScanTarget((*children)[i].Target) == normalizeScanTarget(candidate.Target)) {
			replaced := candidate.ID != "" && candidate.ID != (*children)[i].ID
			if candidate.ID != "" {
				(*children)[i].ID = candidate.ID
			}
			if candidate.Target != "" {
				(*children)[i].Target = candidate.Target
			}
			if candidate.StartedAt != "" {
				(*children)[i].StartedAt = candidate.StartedAt
			}
			if candidate.FinishedAt != "" {
				(*children)[i].FinishedAt = candidate.FinishedAt
			}
			if candidate.Status != "" {
				(*children)[i].Status = candidate.Status
			}
			if candidate.VulnCount > (*children)[i].VulnCount {
				(*children)[i].VulnCount = candidate.VulnCount
			}
			if candidate.TotalTokens > (*children)[i].TotalTokens {
				(*children)[i].TotalTokens = candidate.TotalTokens
			}
			if replaced || candidate.Completion != "" || candidate.PlanPresent || candidate.PlanTasksTotal > 0 {
				(*children)[i].Completion = candidate.Completion
				(*children)[i].StopReason = candidate.StopReason
				(*children)[i].PlanPresent = candidate.PlanPresent
				(*children)[i].PlanTasksTotal = candidate.PlanTasksTotal
				(*children)[i].PlanTasksCompleted = candidate.PlanTasksCompleted
				(*children)[i].PlanTasksSkipped = candidate.PlanTasksSkipped
				(*children)[i].PlanTasksUnfinished = candidate.PlanTasksUnfinished
			}
			return
		}
	}
	*children = append(*children, candidate)
}

// mergePersistedDispatchStopSnapshot reconstructs the strongest durable exact
// snapshot available after a process restart interrupted live-stop draining.
// It never infers identity: every merged physical record must carry the exact
// immutable external instance ID.
func mergePersistedDispatchStopSnapshot(rec *ScanRecord, entries []scanEntry) bool {
	if rec == nil {
		return false
	}
	eventGroups := make([][]WSEvent, 0, len(entries)+1)
	eventGroups = append(eventGroups, rec.Events)
	vulns := append([]VulnSummary(nil), rec.Vulns...)
	children := cloneSubScanSummaries(rec.SubScans)
	matched := false
	for i := range entries {
		candidate := &entries[i].rec
		if candidate.InstanceID != rec.InstanceID {
			continue
		}
		matched = true
		eventGroups = append(eventGroups, candidate.Events)
		for _, vuln := range candidate.Vulns {
			if vuln.SourceScanID == "" {
				vuln.SourceScanID = candidate.ID
			}
			appendVulnSummaryUnique(&vulns, vuln)
		}
		rec.WorkStarted = rec.WorkStarted || candidate.WorkStarted || candidate.ToolCalls > 0 || candidate.Iterations > 0
		if candidate.CurrentPhase > rec.CurrentPhase {
			rec.CurrentPhase = candidate.CurrentPhase
		}
		if candidate.ParentTarget != "" {
			mergeDispatchSubScan(&children, subScanSummaryFromRecord(candidate))
		} else {
			if candidate.SubScanSkipped > rec.SubScanSkipped {
				rec.SubScanSkipped = candidate.SubScanSkipped
			}
			if candidate.Discovery != nil {
				rec.Discovery = cloneSubScanSummary(candidate.Discovery)
			}
		}
		for _, child := range candidate.SubScans {
			mergeDispatchSubScan(&children, child)
		}
	}
	rec.Events = stableDedupeAndSortEvents(eventGroups...)
	rec.Vulns = vulns
	rec.SubScans = children
	rec.Status = "stopped"
	rec.FinishedAt = time.Now().Format(time.RFC3339Nano)
	normalizeTerminalWildcardProgress(rec)
	return matched
}

func (s *Server) claimExactStopNotificationLocked(instanceID string) bool {
	if s.exactStopNotifications == nil {
		s.exactStopNotifications = make(map[string]bool)
	}
	if s.exactStopNotifications[instanceID] {
		return false
	}
	s.exactStopNotifications[instanceID] = true
	return true
}

func (s *Server) stopLiveExactDispatchLocked(instanceID string, inst *ScanInstance) (*ScanRecord, bool, error) {
	inst.mu.Lock()
	if inst.Status == "running" || inst.Status == "pending" || inst.Status == "paused" {
		inst.Status = "stopped"
		inst.StopReason = "user_stopped"
		inst.FinishedAt = time.Now().Format(time.RFC3339Nano)
		normalizeTerminalWildcardInstanceLocked(inst)
		if inst.cancel != nil {
			inst.cancel()
		}
		if inst.agent != nil {
			inst.agent.Stop()
		}
	}
	ensureExactStopEvent(&inst.events, instanceID)
	finalizing := inst.snapshotFinalizing
	ready := inst.snapshotReady
	inst.mu.Unlock()

	rec := s.scanRecordFromInstance(inst)
	if rec == nil {
		return nil, false, errors.New("missing live exact instance snapshot")
	}
	if finalizing && !ready {
		// Durable cancellation intent blocks duplicate dispatch and survives a
		// crash, but remains non-terminal until final findings/events drain.
		rec.Status = "stopping"
		rec.FinishedAt = ""
	}
	delete(s.dispatchReservations, instanceID)
	if err := s.saveExactDispatchSnapshot(rec); err != nil {
		return nil, false, err
	}
	if finalizing && ready {
		inst.mu.Lock()
		inst.snapshotFinalizing = false
		inst.mu.Unlock()
	}
	return rec, s.claimExactStopNotificationLocked(instanceID), nil
}

// cancelExactDispatch is the single serialization point for exact stop versus
// delayed POST registration and session admission. A live stop is persisted as
// non-terminal `stopping` until its event processor and cleanup have drained;
// only the coherent final aggregate is exposed as terminal.
func (s *Server) cancelExactDispatch(instanceID string) (*ScanRecord, bool, error) {
	if !validDispatchID(instanceID) {
		return nil, false, errDispatchSnapshotNotFound
	}

	// The common live path must not wait for a data-directory walk: stopping an
	// active agent has a bounded control-plane deadline. Check under dispatchMu
	// first, then perform legacy/restart reconstruction only when no live owner
	// exists, and recheck after reacquiring the lock.
	s.dispatchMu.Lock()
	s.instancesMu.RLock()
	inst := s.instances[instanceID]
	s.instancesMu.RUnlock()
	if inst != nil {
		rec, notifyListeners, err := s.stopLiveExactDispatchLocked(instanceID, inst)
		s.dispatchMu.Unlock()
		return rec, notifyListeners, err
	}
	s.dispatchMu.Unlock()

	_, aliasRecord := s.findScanByID(instanceID)
	persistedEntries := s.findAllScans()

	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	s.instancesMu.RLock()
	inst = s.instances[instanceID]
	s.instancesMu.RUnlock()
	if inst != nil {
		return s.stopLiveExactDispatchLocked(instanceID, inst)
	}

	// A dashboard record ID is provenance, not external run ownership. Never
	// turn a known canonical alias into a tombstone for some other instance.
	if aliasRecord != nil && aliasRecord.InstanceID != "" && aliasRecord.InstanceID != instanceID {
		return nil, false, errDispatchSnapshotNotFound
	}

	rec, err := s.loadExactDispatchSnapshot(instanceID)
	if err != nil && !errors.Is(err, errDispatchSnapshotNotFound) {
		return nil, false, err
	}
	if rec == nil {
		now := time.Now().Format(time.RFC3339Nano)
		rec = &ScanRecord{
			ID: instanceID, InstanceID: instanceID, StartedAt: now,
			FinishedAt: now, Status: "stopped", StopReason: "exact_stop_tombstone",
			Events: []WSEvent{}, Vulns: []VulnSummary{}, SubScans: []SubScanSummary{},
		}
	} else if !isTerminalScanStatus(rec.Status) {
		if mergePersistedDispatchStopSnapshot(rec, persistedEntries) {
			rec.StopReason = "exact_stop_recovered_after_restart"
		} else {
			rec.StopReason = "exact_stop_before_registration"
		}
	}
	ensureExactStopEvent(&rec.Events, instanceID)
	delete(s.dispatchReservations, instanceID)
	if err := s.saveExactDispatchSnapshot(rec); err != nil {
		return nil, false, err
	}
	return rec, s.claimExactStopNotificationLocked(instanceID), nil
}
