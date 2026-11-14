package web

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/safe"
)

// reservedTopLevelNames are direct children of Data_Dir that hold system
// state, not scan output. The data-dir delete endpoint and the startup sweep
// never remove them, and the retention sweeper and DELETE /api/scans/{id}
// never remove anything inside them except saved scans under _saved (see
// safeToDeleteScanDir). This is the
// single source of truth those destructive paths consult so they cannot
// diverge on what is protected.
var reservedTopLevelNames = map[string]struct{}{
	"logos":      {},
	"_schedules": {},
	"_saved":     {},
	// Uploaded scan-context artifacts (uploads.go) and extracted source
	// archives (uploads_source.go). Scans and schedules reference them by
	// path, so they must outlive any one scan.
	"context":                 {},
	"sources":                 {},
	"auth-profiles.json":      {},
	"auth-profiles.json.lock": {},
	"llm_keys.json":           {},
	".legacy-imported":        {},
}

// reservedTopLevelEntry reports whether name is a Reserved_Entry: an exact
// match against reservedTopLevelNames, any queue_state*.json file, or any
// dotfile / dot-prefixed sentinel. The match ignores case: on a
// case-insensitive filesystem "Sources" opens the same directory as
// "sources".
func reservedTopLevelEntry(name string) bool {
	name = strings.ToLower(name)
	if _, ok := reservedTopLevelNames[name]; ok {
		return true
	}
	if strings.HasPrefix(name, ".") {
		return true
	}
	if strings.HasPrefix(name, "queue_state") && strings.HasSuffix(name, ".json") {
		return true
	}
	return false
}

// retentionCheckInterval is how often the retention sweeper wakes up to
// look for expired scans. Retention is measured in days, so an hourly
// cadence is more than fine and keeps the sweep cheap. The first sweep
// runs immediately on startup so a freshly-configured retention window
// takes effect without waiting a full interval.
const retentionCheckInterval = time.Hour

// startRetentionSweeper runs the background loop that prunes scan output
// directories older than cfg.ScanRetentionDays. It is a no-op (returns
// immediately) when retention is disabled (days <= 0), so the goroutine
// is only kept alive when there is work to do.
//
// The loop honors s.shutdownChan like startScheduler so it tears down
// cleanly when the server stops.
func (s *Server) startRetentionSweeper() {
	if s.cfg == nil || s.cfg.ScanRetentionDays <= 0 {
		return // retention disabled — keep scans forever
	}
	days := s.cfg.ScanRetentionDays
	log.Printf("[RETENTION] Started: pruning scan data older than %d day(s) under %s", days, s.dataDir)

	// Run one sweep immediately so a newly-set retention window applies
	// without waiting a full interval.
	s.pruneExpiredScans(days)

	ticker := time.NewTicker(retentionCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.shutdownChan:
			log.Printf("[RETENTION] Stopping retention sweeper")
			return
		case <-ticker.C:
			s.pruneExpiredScans(days)
		}
	}
}

// scanReferenceTime returns the time a scan should be aged from: the
// finished time when present, otherwise the started time. Both the
// RFC3339 and RFC3339Nano encodings the codebase emits are accepted.
// The zero Time is returned (with ok=false) when neither field parses,
// so callers can choose to skip rather than delete an undatable scan.
func scanReferenceTime(rec ScanRecord) (time.Time, bool) {
	for _, raw := range []string{rec.FinishedAt, rec.StartedAt} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return t, true
		}
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// runningInstanceIDs returns the set of instance IDs whose scan is actually in
// flight (Status "running"/"paused"). Retention uses it so it never deletes a
// live scan's directory.
//
// It reads each instance's Status under inst.mu (the lock its writers hold).
// The previous snapshot treated EVERY non-nil instance as running, but
// completed instances are never removed from s.instances (and
// rebuildInstancesFromDisk repopulates them for every on-disk scan at startup),
// so scanIsRunning returned true for essentially every scan that ever existed —
// silently turning the whole retention feature into a no-op.
func (s *Server) runningInstanceIDs() map[string]bool {
	running := make(map[string]bool)
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()
	for id, inst := range s.instances {
		if inst == nil {
			continue
		}
		inst.mu.RLock()
		active := instanceIsActive(inst.Status)
		inst.mu.RUnlock()
		if active {
			running[id] = true
		}
	}
	return running
}

// pruneExpiredScans deletes scan directories whose reference time is
// older than `days` days. It is safe to call repeatedly and never
// touches reserved/system directories under dataDir (anything outside a
// discovered scan.json tree is left alone, since findAllScans only
// returns directories that actually contain a scan record).
//
// Deletion strategy:
//   - Enumerate scans via findAllScans (the same walk the dashboard and
//     delete handler use), so only real scan output dirs are candidates.
//   - For each expired scan, also remove any child (wildcard subdomain)
//     scan dirs belonging to the same parent, mirroring the manual
//     DELETE /api/scans/{id} semantics.
//   - Skip scans for instances that are currently running so an
//     in-flight scan is never deleted out from under the agent.
//
// Returns the number of top-level scan directories removed (useful for
// tests and log accounting).
func (s *Server) pruneExpiredScans(days int) int {
	defer safe.Recover("retention.prune", "")
	if days <= 0 {
		return 0
	}
	cutoff := time.Now().AddDate(0, 0, -days)

	// Snapshot the set of currently-running instance IDs so we never
	// delete a scan that is mid-flight.
	running := s.runningInstanceIDs()

	entries := s.findAllScans()
	removed := 0
	for _, entry := range entries {
		// Only age from top-level scans; child (wildcard subdomain)
		// records are pruned alongside their parent below.
		if entry.rec.ParentTarget != "" {
			continue
		}
		ref, ok := scanReferenceTime(entry.rec)
		if !ok {
			// Undatable record — fall back to the directory mtime so a
			// malformed/old scan.json still ages out instead of living
			// forever.
			if info, statErr := os.Stat(entry.dir); statErr == nil {
				ref = info.ModTime()
			} else {
				continue
			}
		}
		if ref.After(cutoff) {
			continue // still within retention window
		}
		if scanIsRunning(running, entry.rec) {
			log.Printf("[RETENTION] Skipping running scan %s (%s)", entry.rec.ID, entry.rec.Target)
			continue
		}

		if !s.safeToDeleteScanDir(entry.dir) {
			log.Printf("[RETENTION] Refusing to delete unsafe path %q", entry.dir)
			continue
		}
		if err := os.RemoveAll(entry.dir); err != nil {
			log.Printf("[RETENTION] Failed to delete %s: %v", entry.dir, err)
			continue
		}
		removed++
		log.Printf("[RETENTION] Deleted scan %s (%s), last activity %s",
			entry.rec.ID, entry.rec.Target, ref.Format(time.RFC3339))

		// Remove child (wildcard subdomain) scan dirs of this parent.
		for _, child := range entries {
			if child.dir == entry.dir {
				continue
			}
			if isChildOfScan(&entry.rec, &child.rec) && s.safeToDeleteScanDir(child.dir) {
				_ = os.RemoveAll(child.dir)
			}
		}
	}
	if removed > 0 {
		log.Printf("[RETENTION] Sweep complete: removed %d expired scan dir(s)", removed)
	}
	return removed
}

// scanIsRunning reports whether the scan record corresponds to an
// in-flight instance, checking both the record ID and the parent
// instance ID against the running snapshot.
func scanIsRunning(running map[string]bool, rec ScanRecord) bool {
	return running[rec.ID] || running[rec.InstanceID]
}

// safeToDeleteScanDir guards os.RemoveAll against ever escaping dataDir
// or targeting dataDir itself. The directory must be a strict
// descendant of dataDir (rel is not ".", does not start with "..").
//
// It also refuses anything inside a reserved top-level entry other than
// _saved (which holds saved scans): the scan walk descends into the upload
// stores, so an uploaded artifact or source archive that contains a file
// named scan.json would otherwise look like an expired scan.
func (s *Server) safeToDeleteScanDir(dir string) bool {
	cleanDir := filepath.Clean(dir)
	root := filepath.Clean(s.dataDir)
	if cleanDir == root {
		return false
	}
	rel, err := filepath.Rel(root, cleanDir)
	if err != nil {
		return false
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	first := strings.SplitN(rel, string(os.PathSeparator), 2)[0]
	if !strings.EqualFold(first, "_saved") && reservedTopLevelEntry(first) {
		return false
	}
	return true
}
