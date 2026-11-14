package web

import (
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Typed sentinels returned by resolveDeletableDataDir. The handler maps each
// to an HTTP status (see writeDataDirError): errInvalidScanName → 400,
// errProtectedDataDir → 403, errScanDirNotFound → 404, errNotAScanDir → 400.
var (
	errInvalidScanName  = errors.New("invalid scan name")    // → 400
	errProtectedDataDir = errors.New("protected directory")  // → 403
	errScanDirNotFound  = errors.New("scan not found")       // → 404
	errNotAScanDir      = errors.New("not a scan directory") // → 400
)

// validScanNameRE mirrors the character class sanitizeTarget produces so a
// legitimately-created Scan_Folder name always passes, while anything exotic
// is rejected. The leading-character class excludes a leading "." (closing the
// dotfile vector at the regex layer too) and a leading "-".
var validScanNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

// isPathUnder reports whether childAbs is parentAbs itself or a descendant of
// it. Both arguments are cleaned first, then containment is decided via
// filepath.Rel with a no-".."/no-leading-".." check — the same primitive used
// by resolveScanDirOrNew / safeToDeleteScanDir to keep destructive operations
// from escaping their root.
func isPathUnder(parentAbs, childAbs string) bool {
	parent := filepath.Clean(parentAbs)
	child := filepath.Clean(childAbs)
	if child == parent {
		return true
	}
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	return true
}

// instanceIsActive reports whether a scan instance status means the scan is
// still writing to its directory. Only "running" and "paused" are active
// (case-insensitive); "finished", "stopped", "failed", and "saved" are not and
// therefore do not block deletion of the containing folder.
func instanceIsActive(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running", "paused":
		return true
	default:
		return false
	}
}

// resolveDeletableDataDir turns an untrusted {name} segment into an absolute
// path that is provably a strict single-segment child of Data_Dir and not a
// reserved/system entry, or a typed rejection. It performs every guard before
// any mutating filesystem operation: syntactic rejection runs before any
// syscall, and the Lstat/type/symlink checks run before the caller proceeds.
//
// Order of checks (see design.md → "Path resolution + guards"):
//  1. R2.1 — syntactic rejection (regex + explicit separator/dotdot/NUL/abs).
//  2. R3.1 — reserved/system entries and dotfiles are never deletable.
//  3. R2.2 — strict single-segment containment under Data_Dir.
//  4. R2.3 / R2.4 — existence, type, and symlink checks via os.Lstat
//     (Lstat does NOT follow a final-component symlink).
//  5. The folder must hold scan output (dirHoldsScanRecord); any other
//     directory is "not a scan directory".
func (s *Server) resolveDeletableDataDir(name string) (string, error) {
	// R2.1 — explicit separator / dotdot / NUL / absolute checks, BEFORE
	// touching the filesystem and BEFORE the reserved check. Traversal tokens
	// like "." and ".." begin with a dot, so they must be classified as
	// invalid here rather than being caught by the dotfile rule in
	// reservedTopLevelEntry (which would mislabel them as protected).
	if name == "" || name == "." || name == ".." ||
		strings.ContainsAny(name, `/\`+"\x00") ||
		filepath.IsAbs(name) {
		return "", errInvalidScanName
	}

	// R3.1 — reserved/system entries and dotfiles are never deletable. This
	// runs BEFORE the character-class regex so reserved names that begin with
	// "_" or "." (e.g. "_schedules", "_saved", ".legacy-imported", any dotfile)
	// are reported as protected (403) rather than invalid (400), matching the
	// reserved set shared with the retention sweeper.
	if reservedTopLevelEntry(name) {
		return "", errProtectedDataDir
	}

	// R2.1 — character-class rejection for anything that isn't a legitimate
	// Scan_Folder name (mirrors sanitizeTarget's output; excludes leading
	// "." and "-").
	if !validScanNameRE.MatchString(name) {
		return "", errInvalidScanName
	}

	// R2.2 — strict single-segment containment under Data_Dir.
	root := filepath.Clean(s.dataDir)
	abs := filepath.Clean(filepath.Join(root, name))
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel != name || rel == "." || rel == ".." ||
		strings.ContainsRune(rel, os.PathSeparator) {
		return "", errInvalidScanName
	}

	// R2.3 / R2.4 — existence, type, and symlink checks via Lstat
	// (Lstat does NOT follow a final-component symlink).
	fi, err := os.Lstat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return "", errScanDirNotFound // R1.3
		}
		return "", errScanDirNotFound // unreadable → treat as not found
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", errInvalidScanName // R2.4 — refuse to follow a symlink
	}
	if !fi.IsDir() {
		return "", errNotAScanDir // R2.3
	}
	// Only a folder that holds scan output is a Scan_Folder. Anything else
	// under Data_Dir (an operator's own folder, an empty leftover, state a
	// future feature adds) is refused rather than removed.
	if !dirHoldsScanRecord(abs) {
		return "", errNotAScanDir
	}
	return abs, nil
}

// scanRecordMaxDepth bounds how many directory levels below a top-level folder
// dirHoldsScanRecord searches. Scan folders are <target>/<date>/<slug>, and a
// URL-shaped target adds a few levels ("https:/host/path/..."); 8 covers that
// with room to spare. A record deeper than this makes the folder "not a scan
// directory", which only ever refuses a delete.
const scanRecordMaxDepth = 8

// dirHoldsScanRecord reports whether root holds at least one scan record: a
// regular file named scan.json in root or a directory up to
// scanRecordMaxDepth levels below it. Like walkScanDirs (the scan list's
// discovery walk) it does not follow symlinked directories; unlike it, it
// stops at the first record found and ignores a symlink named scan.json.
func dirHoldsScanRecord(root string) bool {
	return dirHoldsScanRecordDepth(root, scanRecordMaxDepth)
}

func dirHoldsScanRecordDepth(dir string, depth int) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() == "scan.json" && e.Type().IsRegular() {
			return true
		}
	}
	if depth <= 0 {
		return false
	}
	for _, e := range entries {
		if e.IsDir() && dirHoldsScanRecordDepth(filepath.Join(dir, e.Name()), depth-1) {
			return true
		}
	}
	return false
}

// scanFolderHasRunningScan reports whether any active scan instance is still
// writing under folderAbs. It iterates s.instances under a read lock, skipping
// nil and non-active instances, and returns true as soon as an active
// instance's scanDir is equal to or under folderAbs. This is the running-scan
// guard that prevents deleting a folder an in-flight scan still needs (R4.1).
func (s *Server) scanFolderHasRunningScan(folderAbs string) bool {
	folderAbs = filepath.Clean(folderAbs)
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()
	for _, inst := range s.instances {
		if inst == nil {
			continue
		}
		if !instanceIsActive(inst.Status) {
			continue
		}
		if isPathUnder(folderAbs, inst.scanDir) {
			return true
		}
	}
	return false
}

// pruneInstancesUnder cancels and removes every in-memory instance whose
// scanDir is equal to or under folderAbs, so the live instance list does not
// retain a stale entry pointing at deleted files (R1.2). By the time this runs
// the running-scan guard (scanFolderHasRunningScan) has already ensured no
// active instance is under folderAbs, so this only reaps finished/stopped
// records. It takes the write lock since it mutates s.instances.
func (s *Server) pruneInstancesUnder(folderAbs string) {
	folderAbs = filepath.Clean(folderAbs)
	s.instancesMu.Lock()
	defer s.instancesMu.Unlock()
	for id, inst := range s.instances {
		if inst == nil {
			continue
		}
		if isPathUnder(folderAbs, inst.scanDir) {
			if inst.cancel != nil {
				inst.cancel()
			}
			delete(s.instances, id)
		}
	}
}

// handleDeleteDataDir implements DELETE /api/data-dirs/{name}: it recursively
// removes one top-level Scan_Folder under Data_Dir. Every destructive step is
// gated by a guard that runs before os.RemoveAll — method, name resolution
// (syntactic/reserved/containment/symlink), and the running-scan check — so a
// rejected request performs no filesystem mutation. The route sits behind the
// existing authMiddleware + CSRF checks (registered on the mux), so this
// handler never reimplements auth.
//
// Status mapping (see design.md → "Error Handling"):
//
//	method != DELETE            → 405 (plain text)
//	resolution sentinel         → 400/403/404 via writeDataDirError
//	running scan under folder   → 409 {"error":"scan is running"}
//	os.RemoveAll failure         → 500 {"error":"delete failed"} (logged, R6.2)
//	success                     → 200 {"status":"deleted","name":name} (R1.1)
func (s *Server) handleDeleteDataDir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed) // R1.4
		return
	}
	// net/http has already percent-decoded r.URL.Path; {name} is the remainder
	// after the subtree-match prefix. A trailing-slash or empty segment yields
	// an empty name, which resolveDeletableDataDir rejects as invalid.
	name := strings.TrimPrefix(r.URL.Path, "/api/data-dirs/")

	absPath, err := s.resolveDeletableDataDir(name)
	if err != nil {
		writeDataDirError(w, err) // maps sentinel → 400/403/404 (routine refusal, not error-logged)
		return
	}
	if s.scanFolderHasRunningScan(absPath) {
		writeJSONStatus(w, http.StatusConflict,
			map[string]string{"error": "scan is running"}) // R4.1
		return
	}
	if rmErr := os.RemoveAll(absPath); rmErr != nil {
		log.Printf("[data-dirs] delete %q failed: %v", absPath, rmErr) // R6.2 — failure after all checks passed
		writeJSONStatus(w, http.StatusInternalServerError,
			map[string]string{"error": "delete failed"})
		return
	}
	log.Printf("[data-dirs] deleted scan folder %q (%s)", name, absPath) // R6.1
	s.pruneInstancesUnder(absPath)                                       // R1.2
	writeJSONStatus(w, http.StatusOK,
		map[string]string{"status": "deleted", "name": name}) // R1.1
}

// writeDataDirError maps a resolveDeletableDataDir sentinel to its HTTP status
// and JSON body per the design's error table. These are routine refusals and
// are intentionally NOT error-logged (R6.2); only a post-check os.RemoveAll
// failure is logged at error level (see handleDeleteDataDir). Any unrecognized
// error falls through to 400 invalid scan name.
func writeDataDirError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errProtectedDataDir):
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "protected directory"})
	case errors.Is(err, errScanDirNotFound):
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
	case errors.Is(err, errNotAScanDir):
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "not a scan directory"})
	default: // errInvalidScanName and any unrecognized error
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid scan name"})
	}
}
