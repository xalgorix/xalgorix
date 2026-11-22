package web

import (
	"errors"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

const (
	// stopReasonRestartResuming marks a scan that restart recovery found
	// interrupted and queued for automatic resume. Its status is "pending":
	// the scan is waiting to continue, not stopped.
	stopReasonRestartResuming = "server_restart_resuming"
	// stopReasonRestartNoResumeState marks an interrupted scan that restart
	// recovery cannot resume because its queue state is missing.
	stopReasonRestartNoResumeState = "server_restart_no_resume_state"
	// stopReasonRestartResumeFailed marks a scan whose automatic resume after
	// a restart could not start. It is final, so pollers stop waiting on it.
	stopReasonRestartResumeFailed = "server_restart_resume_failed"
)

// errRestartResumeNoTargets refuses the resume of a saved queue with no
// targets left. Every later start would refuse it the same way.
var errRestartResumeNoTargets = errors.New("the saved queue has no targets left")

// markDispatchSnapshotResuming gives the durable exact snapshot of an
// instance that restart recovery queued for resume the same pending status as
// its scan.json. A graceful shutdown leaves the snapshot "stopped" with a
// signal or shutdown reason, and nothing rewrites it until the resumed run
// reaches work admission, which can be a long wait in the admission queue.
// Readers that fall back to the snapshot would report a scan that is about to
// resume as stopped. A tombstone, a paused snapshot, or a snapshot that is
// already pending is left as it is.
func (s *Server) markDispatchSnapshotResuming(instanceID string) {
	instanceID = strings.TrimSpace(instanceID)
	if !validDispatchID(instanceID) {
		return
	}
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	snapshot, err := s.loadExactDispatchSnapshot(instanceID)
	if err != nil {
		if !errors.Is(err, errDispatchSnapshotNotFound) {
			log.Printf("[AUTO-RESUME] leaving unreadable exact snapshot %q as it is: %v", instanceID, err)
		}
		return
	}
	if isDispatchTombstone(snapshot) || !isInterruptedRecoverableRecord(snapshot.Status, snapshot.StopReason) {
		return
	}
	if strings.EqualFold(snapshot.Status, "pending") && snapshot.StopReason == stopReasonRestartResuming && snapshot.FinishedAt == "" {
		return
	}
	snapshot.Status = "pending"
	snapshot.StopReason = stopReasonRestartResuming
	snapshot.FinishedAt = ""
	if err := s.saveExactDispatchSnapshot(snapshot); err != nil {
		log.Printf("[AUTO-RESUME] could not mark exact snapshot %q as resuming: %v", instanceID, err)
	}
}

// recordRestartResumeStarted moves the durable records of a resumed scan from
// the restart-recovery pending state to running once the resumed run has an
// admission slot. Single-target sessions rewrite their own scan.json when
// they start, but a resumed wildcard parent is never rewritten by a session,
// so without this it kept the pending status and the recovery marker for the
// whole resumed run, and a parent that later finished with unresolved
// children was saved as stopped with that marker.
func (s *Server) recordRestartResumeStarted(run *multiScanRun) {
	if run == nil || !run.req.IsResume || !instanceIsRunning(run.instance) {
		// A stop that landed between admission and here owns the records.
		return
	}
	seen := make(map[string]bool, 2)
	for _, dir := range []string{run.req.ResumeScanDir, run.placeholderDir} {
		if dir == "" {
			continue
		}
		clean := filepath.Clean(dir)
		if seen[clean] {
			continue
		}
		seen[clean] = true
		s.markScanDirResumeRunning(clean)
	}

	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	snapshot, err := s.loadExactDispatchSnapshot(run.instanceID)
	if err != nil || !strings.EqualFold(snapshot.Status, "pending") || snapshot.StopReason != stopReasonRestartResuming {
		// No snapshot, or one an exact stop or the run itself already
		// replaced. A tombstone must never be overwritten from here.
		return
	}
	if !instanceIsRunning(run.instance) {
		return
	}
	if err := s.persistExactInstanceSnapshotLocked(run.instance); err != nil {
		log.Printf("[AUTO-RESUME] could not record running exact snapshot for %s: %v", run.instanceID, err)
	}
}

func instanceIsRunning(inst *ScanInstance) bool {
	if inst == nil {
		return false
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	return inst.Status == "running"
}

// markScanDirResumeRunning rewrites the scan.json at dir from the restart
// recovery pending state to running. It touches only a record that still
// carries the recovery marker and is not terminal.
func (s *Server) markScanDirResumeRunning(dir string) {
	rec, ok := loadScanRecordForRewrite(dir)
	if !ok || rec.StopReason != stopReasonRestartResuming || isTerminalScanStatus(rec.Status) {
		return
	}
	rec.Status = "running"
	rec.StopReason = ""
	rec.FinishedAt = ""
	s.saveScanRecordTo(rec, dir)
	s.invalidateScanListCache()
}

// autoResumeInterruptedQueues resumes every scan queue that a restart
// interrupted. It runs once, shortly after startup. A queue whose resume is
// refused for good is given a final status instead of being left pending with
// no run behind it (see failRestartResume).
//
// A scan already running or queued does not block it. Each resumed queue
// registers its own instance and waits for a slot in the admission loop, so
// it can run beside a scheduled scan or an API dispatch that started first.
// It used to skip every queue in that case, which left the pending
// placeholders that restart recovery installed with no run behind them. Only
// a queue that something else already runs or resumes is left alone; see
// queueResumeSkipReasonLocked.
func (s *Server) autoResumeInterruptedQueues() {
	s.queueResumeMu.Lock()
	defer s.queueResumeMu.Unlock()
	var entries []queueStateEntry
	for _, entry := range autoResumeQueueEntries(s.validQueueStateEntries(true)) {
		if reason := s.queueResumeSkipReasonLocked(entry); reason != "" {
			log.Printf("[AUTO-RESUME] Leaving scan queue %s alone: %s", queueResumeEntryKey(entry), reason)
			continue
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return
	}
	log.Printf("[AUTO-RESUME] Resuming %d interrupted scan queue(s)", len(entries))
	for _, entry := range entries {
		if s.stopReq.Load() {
			break
		}
		req := scanRequestFromQueueState(entry.state, entry.path)
		instanceID := entry.state.InstanceID
		if len(req.Targets) == 0 {
			s.failRestartResume(instanceID, errRestartResumeNoTargets)
			continue
		}
		log.Printf("[AUTO-RESUME] Resuming interrupted scan queue %s: %d targets from index %d", instanceID, len(req.Targets), entry.state.CurrentIdx)
		scanCfg := *s.cfg
		resumeKey := queueResumeEntryKey(entry)
		s.markQueueResumeLaunchingLocked(resumeKey)
		go func(r ScanRequest, cfg config.Config, id string, key string) {
			defer s.clearQueueResumeLaunching(key)
			run, err := s.registerMultiScan(r, id)
			if err != nil {
				s.failRestartResume(id, err)
				return
			}
			if s.runResumedQueueFn != nil {
				s.runResumedQueueFn(run, &cfg)
				return
			}
			s.runRegisteredMultiScan(run, &cfg)
		}(req, scanCfg, instanceID, resumeKey)
	}
}

// restartResumeRefusedForGood reports whether a refused resume would be
// refused the same way on every later start: the durable exact snapshot is a
// tombstone or cannot be used, or the saved queue has no targets left. Any
// other refusal, such as a lock directory that can't be created, a file
// descriptor limit, or an I/O error reading the snapshot, can clear on its
// own, so the scan keeps its queue state and the next start retries it.
func restartResumeRefusedForGood(cause error) bool {
	var tombstoned *tombstonedDispatchError
	var corrupt *corruptDispatchSnapshotError
	return errors.As(cause, &tombstoned) || errors.As(cause, &corrupt) || errors.Is(cause, errRestartResumeNoTargets)
}

// failRestartResume settles the restart-recovery placeholder of a queue whose
// automatic resume could not start. A queue that another run or process
// drives is left alone, and so is one whose refusal may clear on its own (see
// restartResumeRefusedForGood): it stays pending with its queue state, and the
// next start retries it. A durable exact stop gives the placeholder that stop;
// any other permanent refusal marks it failed. The stop is recorded in the
// scan.json and the exact snapshot. The queue state is cleared only once the
// final status is durable, so the next start does not retry a resume that is
// known to be refused, and a scan never loses its queue state (for a wildcard
// scan, its only copy of the subdomain list) without a final status.
//
// No completion notification is sent: the scan did not finish.
func (s *Server) failRestartResume(instanceID string, cause error) {
	if errors.Is(cause, errQueueOwnedElsewhere) || errors.Is(cause, errInstanceIDInUse) {
		log.Printf("[AUTO-RESUME] Not resuming %s here: %v", instanceID, cause)
		return
	}
	if !restartResumeRefusedForGood(cause) {
		log.Printf("[AUTO-RESUME] Resume of %s could not start; it stays pending with its queue state and the next start retries it: %v", instanceID, cause)
		return
	}
	log.Printf("[AUTO-RESUME] Resume of %s was refused: %v", instanceID, cause)
	s.instancesMu.RLock()
	inst := s.instances[instanceID]
	s.instancesMu.RUnlock()
	if inst == nil {
		return
	}

	status, stopReason := "failed", stopReasonRestartResumeFailed
	finishedAt := time.Now().Format(time.RFC3339Nano)
	var tombstoned *tombstonedDispatchError
	if errors.As(cause, &tombstoned) && tombstoned.snapshot != nil {
		status, stopReason, finishedAt = tombstoneStop(tombstoned.snapshot)
	}

	inst.mu.Lock()
	placeholder := inst.Status == "pending" && inst.agent == nil && inst.cancel == nil && inst.StopReason == stopReasonRestartResuming
	if !placeholder {
		// A stop or another resume already settled it.
		inst.mu.Unlock()
		return
	}
	inst.Status = status
	inst.StopReason = stopReason
	inst.FinishedAt = finishedAt
	normalizeTerminalWildcardInstanceLocked(inst)
	dir := inst.scanDir
	inst.mu.Unlock()

	snapshotDurable := true // a tombstone already is
	if tombstoned == nil {
		// Buffer the event before the snapshot is written so it is part of it.
		s.broadcastToInstance(instanceID, WSEvent{Type: "error", Content: "The automatic resume after a server restart could not start; the scan is marked failed."})
		if err := s.persistExactInstanceSnapshot(inst); err != nil && validDispatchID(instanceID) {
			snapshotDurable = false
			log.Printf("[AUTO-RESUME] could not record failed resume in the exact snapshot for %s: %v", instanceID, err)
		}
	}
	s.persistStopToScanDir(dir, status, stopReason, finishedAt)
	if snapshotDurable {
		if err := s.clearQueueStateDurable(instanceID); err != nil {
			log.Printf("[AUTO-RESUME] could not clear queue state for %s: %v", instanceID, err)
		}
	} else {
		log.Printf("[AUTO-RESUME] keeping the queue state of %s: its final status is not in the exact snapshot", instanceID)
	}
	s.invalidateScanListCache()
	s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
}

// settleResumingDispatchSnapshot writes a final status into instanceID's
// exact snapshot when restart recovery left it pending with the resuming
// marker and no run will replace it. Without this the snapshot stayed pending
// for good, so /snapshot answered 404 and a re-dispatch was told the scan was
// pending. Any other snapshot, such as a tombstone or one a run or an exact
// stop already wrote, is left as it is. When inst is set its whole state is
// written; otherwise only the status fields change.
func (s *Server) settleResumingDispatchSnapshot(instanceID string, inst *ScanInstance, status, stopReason, finishedAt string) {
	instanceID = strings.TrimSpace(instanceID)
	if !validDispatchID(instanceID) {
		return
	}
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	snapshot, err := s.loadExactDispatchSnapshot(instanceID)
	if err != nil || !strings.EqualFold(snapshot.Status, "pending") || snapshot.StopReason != stopReasonRestartResuming {
		return
	}
	if inst != nil {
		err = s.persistExactInstanceSnapshotLocked(inst)
	} else {
		snapshot.Status = status
		snapshot.StopReason = stopReason
		snapshot.FinishedAt = finishedAt
		err = s.saveExactDispatchSnapshot(snapshot)
	}
	if err != nil {
		log.Printf("[AUTO-RESUME] could not record %s/%s in the exact snapshot for %s: %v", status, stopReason, instanceID, err)
	}
}
