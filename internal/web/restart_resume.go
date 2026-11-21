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
	if run == nil || !run.req.IsResume {
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
	run.instance.mu.RLock()
	running := run.instance.Status == "running"
	run.instance.mu.RUnlock()
	if !running {
		return
	}
	if err := s.persistExactInstanceSnapshotLocked(run.instance); err != nil {
		log.Printf("[AUTO-RESUME] could not record running exact snapshot for %s: %v", run.instanceID, err)
	}
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
// interrupted. It runs once, shortly after startup. A queue whose resume
// cannot start is given a final status instead of being left pending with no
// run behind it.
func (s *Server) autoResumeInterruptedQueues() {
	s.queueResumeMu.Lock()
	defer s.queueResumeMu.Unlock()
	if s.running.Load() || s.hasQueueResumeLaunchingLocked() {
		log.Printf("[AUTO-RESUME] Skipping — a scan execution is already active.")
		return
	}
	entries := autoResumeQueueEntries(s.validQueueStateEntries(true))
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
			s.failRestartResume(instanceID, errors.New("the saved queue has no targets left"))
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

// failRestartResume settles the restart-recovery placeholder of a queue whose
// automatic resume could not start. A queue that another run or process
// drives is left alone. A durable exact stop gives the placeholder that stop;
// any other refusal marks it failed. Either way the stop is recorded in the
// scan.json and the exact snapshot, and the queue state is cleared so the
// next start does not retry a resume that is known to be refused.
//
// No completion notification is sent: the scan did not finish.
func (s *Server) failRestartResume(instanceID string, cause error) {
	if errors.Is(cause, errQueueOwnedElsewhere) || errors.Is(cause, errInstanceIDInUse) {
		log.Printf("[AUTO-RESUME] Not resuming %s here: %v", instanceID, cause)
		return
	}
	log.Printf("[AUTO-RESUME] Resume of %s could not start: %v", instanceID, cause)
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

	if tombstoned == nil {
		// Buffer the event before the snapshot is written so it is part of it.
		s.broadcastToInstance(instanceID, WSEvent{Type: "error", Content: "The automatic resume after a server restart could not start; the scan is marked failed."})
		if err := s.persistExactInstanceSnapshot(inst); err != nil && validDispatchID(instanceID) {
			log.Printf("[AUTO-RESUME] could not record failed resume in the exact snapshot for %s: %v", instanceID, err)
		}
	}
	s.persistStopToScanDir(dir, status, stopReason, finishedAt)
	if err := s.clearQueueStateDurable(instanceID); err != nil {
		log.Printf("[AUTO-RESUME] could not clear queue state for %s: %v", instanceID, err)
	}
	s.invalidateScanListCache()
	s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
}
