package scanctx

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/xalgord/xalgorix/v4/internal/storage"
)

type coveragePair struct {
	Endpoint string `json:"endpoint"`
	Class    string `json:"class"`
}

type coverageCheckpoint struct {
	Version  int            `json:"version"`
	Executed []coveragePair `json:"executed"`
	Verified []coveragePair `json:"verified"`
}

func coveragePairs(matrix map[string]map[string]struct{}) []coveragePair {
	var pairs []coveragePair
	for endpoint, classes := range matrix {
		for class := range classes {
			pairs = append(pairs, coveragePair{endpoint, class})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Endpoint != pairs[j].Endpoint {
			return pairs[i].Endpoint < pairs[j].Endpoint
		}
		return pairs[i].Class < pairs[j].Class
	})
	return pairs
}

// SaveCheckpoint serializes shared evidence under its lock. Concurrent lane
// writers cannot replace a newer matrix with an older snapshot.
func (s *CoverageStore) SaveCheckpoint(dir string) error {
	if s == nil || dir == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(coverageCheckpoint{1, coveragePairs(s.pairs), coveragePairs(s.verified)})
	if err != nil {
		return err
	}
	return storage.WriteAtomic(filepath.Join(dir, "coverage.json"), data)
}

// LoadCheckpoint restores only executed evidence, retaining the distinction
// between raw probes and deterministic verifier attribution.
func (s *CoverageStore) LoadCheckpoint(dir string) error {
	if s == nil || dir == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(dir, "coverage.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved coverageCheckpoint
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	if saved.Version != 1 {
		return fmt.Errorf("unsupported coverage checkpoint version %d", saved.Version)
	}
	for _, pair := range saved.Executed {
		s.Mark(pair.Endpoint, pair.Class)
	}
	for _, pair := range saved.Verified {
		s.MarkVerified(pair.Endpoint, pair.Class)
	}
	return nil
}
