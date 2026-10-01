package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/storage"
)

type findingCheckpoint struct {
	Version  int             `json:"version"`
	ScanID   string          `json:"scan_id"`
	Sequence int             `json:"sequence"`
	Findings []Vulnerability `json:"findings"`
}

func nextFindingIDLocked(store *vulnStore) string {
	used := make(map[string]bool, len(store.vulns))
	for _, v := range store.vulns {
		used[v.ID] = true
		if n, err := strconv.Atoi(strings.TrimPrefix(v.ID, "XALG-")); err == nil && n > store.nextSequence {
			store.nextSequence = n
		}
	}
	for {
		store.nextSequence++
		id := fmt.Sprintf("XALG-%d", store.nextSequence)
		if !used[id] {
			return id
		}
	}
}

func (store *vulnStore) persistLocked() error {
	if store.persistPath == "" {
		return nil
	}
	data, err := json.Marshal(findingCheckpoint{1, store.scanID, store.nextSequence, store.vulns})
	if err != nil {
		return err
	}
	return storage.WriteAtomic(store.persistPath, data)
}

// RestoreContext restores deduplication and identity state before the first
// report. Existing legacy collisions are preserved; new IDs exceed every
// saved sequence, including gaps, rather than restarting at list length.
func RestoreContext(contextID, dir string, legacy []Vulnerability) error {
	if contextID == "" || dir == "" {
		return nil
	}
	if err := storage.EnsureSecureDir(dir); err != nil {
		return err
	}
	store := getStoreForContext(contextID)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.persistPath = filepath.Join(dir, "findings.json")
	store.scanID = contextID
	data, err := os.ReadFile(store.persistPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		var saved findingCheckpoint
		if err := json.Unmarshal(data, &saved); err != nil {
			return err
		}
		if saved.Version != 1 || saved.ScanID != contextID || saved.Sequence < 0 {
			return fmt.Errorf("invalid or incompatible finding checkpoint")
		}
		store.vulns = saved.Findings
		store.nextSequence = saved.Sequence
	}
	for _, v := range legacy {
		if _, _, duplicate := findDuplicateVulnerability(store.vulns, v.Title, v.Description, v.CVE, v.CWE, v.Target, v.Endpoint); !duplicate {
			store.vulns = append(store.vulns, v)
		}
	}
	return store.persistLocked()
}
