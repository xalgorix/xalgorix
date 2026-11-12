package web

import (
	"errors"
	"log"
	"path/filepath"
	"strings"
	"time"
)

// isPersistableStop reports whether status and stopReason describe a stop
// that a scan.json must record: a stop or failure meant as final. A
// recoverable interruption (shutdown, signal, panic) is left to restart
// recovery, which may resume it.
func isPersistableStop(status, stopReason string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "stopped", "failed":
		return !isInterruptedRecoverableRecord(status, stopReason)
	default:
		return false
	}
}

// loadScanRecordForRewrite loads the scan.json at dir in the shape its
// writers keep it: a journal-backed record with its recent event tail inline,
// or a legacy record with its whole embedded event log, which a rewrite must
// keep. A journal that cannot be read does not block the rewrite; the record
// is rewritten without an inline tail, as restart recovery already does.
func loadScanRecordForRewrite(dir string) (*ScanRecord, bool) {
	rec, ok := readScanSummary(filepath.Join(dir, "scan.json"))
	if !ok {
		return nil, false
	}
	if !rec.EventsJournal {
		return loadScanRecordFromDir(dir)
	}
	tail := make([]WSEvent, 0, detailEventTail)
	total, _, err := walkEventJournal(dir, func(_ int, event WSEvent) { tail = appendEventTail(tail, event) })
	if err != nil {
		log.Printf("[scan] rewriting %s without its event tail: %v", dir, err)
		return rec, true
	}
	rec.Events = tail
	rec.EventsTotal = total
	rec.EventsTruncated = total > len(tail)
	return rec, true
}

// persistStopToScanDir records a final stop in the scan.json at dir while
// that file still says the scan is paused, pending or running. It is for
// scans that no session writes any more; a running session records its own
// stop when it ends. It reports whether it rewrote the file.
func (s *Server) persistStopToScanDir(dir, status, stopReason, finishedAt string) bool {
	if dir == "" || !isPersistableStop(status, stopReason) {
		return false
	}
	rec, ok := loadScanRecordForRewrite(dir)
	if !ok || isTerminalScanStatus(rec.Status) {
		return false
	}
	if finishedAt == "" {
		finishedAt = time.Now().Format(time.RFC3339Nano)
	}
	previous := rec.Status
	rec.Status = status
	rec.StopReason = stopReason
	rec.FinishedAt = finishedAt
	normalizeTerminalWildcardProgress(rec)
	s.saveScanRecordTo(rec, dir)
	s.invalidateScanListCache()
	log.Printf("[scan] recorded %s/%s over %s in %s", status, stopReason, previous, filepath.Join(dir, "scan.json"))
	return true
}

// persistIdleInstanceStop records a stopped instance's final status in its
// scan.json when no scan session will write that file again: the instance
// was rebuilt from disk after a restart, or its run has exited, as a paused
// scan's has. A live run records the stop itself as its sessions and exit
// path finish. Without this a restart rebuilt a stopped paused scan from its
// scan.json as paused, and it could be resumed.
func (s *Server) persistIdleInstanceStop(inst *ScanInstance) {
	if inst == nil {
		return
	}
	inst.mu.RLock()
	idle := inst.agent == nil && inst.cancel == nil && (!inst.snapshotFinalizing || inst.snapshotReady)
	dir, status, stopReason, finishedAt := inst.scanDir, inst.Status, inst.StopReason, inst.FinishedAt
	inst.mu.RUnlock()
	if idle {
		s.persistStopToScanDir(dir, status, stopReason, finishedAt)
	}
}

// isDispatchTombstone reports whether a durable exact snapshot forbids any
// further run under its instance ID. runMultiScan refuses a dispatch whose
// snapshot is terminal or stopping, unless an auto-resume continues a
// recoverable interruption.
func isDispatchTombstone(snapshot *ScanRecord) bool {
	if snapshot == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(snapshot.Status), "stopping") {
		return true
	}
	return isTerminalScanStatus(snapshot.Status) && !isInterruptedRecoverableRecord(snapshot.Status, snapshot.StopReason)
}

// dispatchTombstone returns the durable exact snapshot for instanceID when it
// is a tombstone, and nil otherwise. Results, misses included, are cached in
// seen so a restart reads each snapshot once.
func (s *Server) dispatchTombstone(instanceID string, seen map[string]*ScanRecord) *ScanRecord {
	instanceID = strings.TrimSpace(instanceID)
	if !validDispatchID(instanceID) {
		return nil
	}
	if snapshot, ok := seen[instanceID]; ok {
		return snapshot
	}
	var tombstone *ScanRecord
	snapshot, err := s.loadExactDispatchSnapshot(instanceID)
	switch {
	case err == nil && isDispatchTombstone(snapshot):
		tombstone = snapshot
	case err != nil && !errors.Is(err, errDispatchSnapshotNotFound):
		log.Printf("[scan] ignoring unreadable exact dispatch snapshot %q during restart recovery: %v", instanceID, err)
	}
	seen[instanceID] = tombstone
	return tombstone
}

// applyDispatchTombstone gives a scan record that is still paused, pending or
// running the stop recorded in its instance's tombstone snapshot. An exact
// stop records the stop in the dispatch snapshot only, so after a restart the
// scan.json alone would bring a stopped scan back as paused or resumable. It
// reports whether it changed rec.
func (s *Server) applyDispatchTombstone(rec *ScanRecord, seen map[string]*ScanRecord) bool {
	if rec == nil || isTerminalScanStatus(rec.Status) {
		return false
	}
	tombstone := s.dispatchTombstone(rec.InstanceID, seen)
	if tombstone == nil {
		return false
	}
	rec.Status, rec.StopReason, rec.FinishedAt = tombstoneStop(tombstone)
	normalizeTerminalWildcardProgress(rec)
	return true
}

// tombstoneStop returns the status, stop reason and finish time that a
// tombstone snapshot gives a record or instance that never finished on its
// own: stopped (or failed), even when the queue as a whole ended differently.
func tombstoneStop(tombstone *ScanRecord) (status, stopReason, finishedAt string) {
	status = terminalSubScanStatus(tombstone.Status)
	stopReason = tombstone.StopReason
	switch {
	case strings.EqualFold(strings.TrimSpace(tombstone.Status), "stopping") &&
		(stopReason == "" || !isPersistableStop(status, stopReason)):
		// Only an exact stop writes a stopping snapshot.
		stopReason = "user_stopped"
	case stopReason == "":
		stopReason = "exact_dispatch_terminal"
	}
	finishedAt = tombstone.FinishedAt
	if finishedAt == "" {
		finishedAt = time.Now().Format(time.RFC3339Nano)
	}
	return status, stopReason, finishedAt
}

// settlePausedInstanceTombstone gives a paused instance the stop recorded in
// its tombstone snapshot, after a resume was refused because of it. The
// snapshot is what the control plane was told, so the instance must stop
// reading as paused and resumable, in memory and in its scan.json.
func (s *Server) settlePausedInstanceTombstone(inst *ScanInstance, tombstone *ScanRecord) {
	if inst == nil || !isDispatchTombstone(tombstone) {
		return
	}
	status, stopReason, finishedAt := tombstoneStop(tombstone)
	inst.mu.Lock()
	if inst.Status != "paused" {
		inst.mu.Unlock()
		return
	}
	inst.Status = status
	inst.StopReason = stopReason
	inst.FinishedAt = finishedAt
	normalizeTerminalWildcardInstanceLocked(inst)
	inst.mu.Unlock()
	s.persistIdleInstanceStop(inst)
}
