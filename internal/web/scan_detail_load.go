// Package web — streaming loaders for the scan-detail read path.
//
// A finished scan's scan.json embeds the entire event log (every LLM message
// and raw tool stdout), which for a high-token scan can be hundreds of MB. The
// old GET /api/scans/{id} path json.Unmarshalled that whole file into
// ScanRecord (decoding millions of WSEvent struct fields) and then re-marshaled
// it — so opening one big scan could hang the handler for minutes.
//
// These loaders walk scan.json ONCE with a streaming decoder, decode only the
// small metadata fields, count the events, and materialize just the slice of
// events the caller needs (a tail for the detail view, or an offset/limit
// window for lazy paging). Event elements outside the requested slice are never
// decoded into structs and never held in memory.
package web

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// detailEventTail is how many of the most recent events GET /api/scans/{id}
// returns inline. Enough to render a useful activity tail immediately; older
// events are paged on demand via GET /api/scans/{id}/events.
const detailEventTail = 300

// maxEventsWindow bounds a single lazy events page so a caller can't ask the
// server to materialize an unbounded slice.
const maxEventsWindow = 1000

// walkScanJSON streams the scan.json object at path. Non-"events" top-level
// fields are captured (undecoded) into meta; every element of the "events"
// array is passed to onEvent by index. It returns the total event count. The
// whole file is read but only metadata + whatever onEvent retains stays live.
func walkScanJSON(path string, onEvent func(idx int, raw json.RawMessage)) (map[string]json.RawMessage, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	dec := json.NewDecoder(bufio.NewReaderSize(f, 1<<20))
	meta := make(map[string]json.RawMessage, 32)
	total := 0

	// Opening '{'.
	if _, err := dec.Token(); err != nil {
		return nil, 0, err
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, 0, err
		}
		key, _ := keyTok.(string)
		if key == "events" {
			// The value is either an array or null.
			t, err := dec.Token()
			if err != nil {
				return nil, 0, err
			}
			if d, ok := t.(json.Delim); ok && d == '[' {
				if onEvent == nil {
					// Summary mode: skip the events array by token depth without
					// materializing any element. Critically this avoids copying a
					// multi-hundred-MB events blob into memory (the old
					// ReadFile + scanRecordLite path did exactly that on every
					// cache-cold walk, thrashing GC near GOMEMLIMIT). Element
					// strings are tokenized transiently and GC'd one at a time.
					depth := 1
					for depth > 0 {
						tok, err := dec.Token()
						if err != nil {
							return nil, 0, err
						}
						if delim, ok := tok.(json.Delim); ok {
							switch delim {
							case '[', '{':
								depth++
							case ']', '}':
								depth--
							}
						}
					}
				} else {
					for dec.More() {
						var raw json.RawMessage
						if err := dec.Decode(&raw); err != nil {
							return nil, 0, err
						}
						onEvent(total, raw)
						total++
					}
					// Closing ']'.
					if _, err := dec.Token(); err != nil {
						return nil, 0, err
					}
				}
			}
			// else: null (or unexpected) → no events.
			continue
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, 0, err
		}
		meta[key] = raw
	}
	return meta, total, nil
}

// recordFromMeta rebuilds a ScanRecord from the captured non-event fields.
func recordFromMeta(meta map[string]json.RawMessage) (*ScanRecord, error) {
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	var rec ScanRecord
	if err := json.Unmarshal(metaBytes, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func decodeEvents(raws []json.RawMessage) []WSEvent {
	events := make([]WSEvent, 0, len(raws))
	for _, r := range raws {
		var e WSEvent
		if json.Unmarshal(r, &e) == nil {
			events = append(events, e)
		}
	}
	return events
}

// scanMetaFile is a small sidecar next to scan.json holding exactly what the
// detail view needs: the scan metadata plus only the last detailEventTail
// events and the true event count. Reading it is O(tail) instead of streaming
// the whole (possibly hundreds-of-MB) scan.json, which is what makes opening a
// large scan instant — the same shape the SaaS gets for free from Postgres.
// scan.json remains the full source of truth (reports, full-event consumers).
const scanMetaFile = "scan.meta.json"

// buildDetailMeta returns a light copy of rec carrying only the tail of events
// plus the total/truncation hints — the exact payload the detail view needs.
func buildDetailMeta(rec *ScanRecord) *ScanRecord {
	light := *rec
	total := max(rec.EventsTotal, len(rec.Events))
	if len(rec.Events) > detailEventTail {
		light.Events = append([]WSEvent(nil), rec.Events[len(rec.Events)-detailEventTail:]...)
	} else {
		light.Events = append([]WSEvent(nil), rec.Events...)
	}
	light.EventsTotal = total
	light.EventsTruncated = total > len(light.Events)
	return &light
}

// writeScanDetailMeta persists the detail sidecar for a full record. Best-effort:
// a failure just means the next detail read falls back to streaming scan.json.
func writeScanDetailMeta(dir string, rec *ScanRecord) {
	if dir == "" || rec == nil {
		return
	}
	writeScanDetailMetaLight(dir, buildDetailMeta(rec))
}

// writeScanDetailMetaLight writes an already-trimmed light record atomically.
func writeScanDetailMetaLight(dir string, light *ScanRecord) {
	if dir == "" || light == nil {
		return
	}
	data, err := json.Marshal(light)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".scanmeta-*.tmp")
	if err != nil {
		return
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return
	}
	// Atomic replace so a concurrent reader never sees a half-written sidecar.
	if err := os.Rename(tmpPath, filepath.Join(dir, scanMetaFile)); err != nil {
		_ = os.Remove(tmpPath)
	}
}

// readScanDetailMeta loads the detail sidecar if present and current. It is
// considered stale (and ignored) when scan.json is newer, so a scan.json
// written by a path that didn't refresh the sidecar can't serve stale data.
func readScanDetailMeta(dir string) (*ScanRecord, bool) {
	if dir == "" {
		return nil, false
	}
	metaPath := filepath.Join(dir, scanMetaFile)
	metaInfo, err := os.Stat(metaPath)
	if err != nil {
		return nil, false
	}
	if srcInfo, err := os.Stat(filepath.Join(dir, "scan.json")); err == nil {
		if srcInfo.ModTime().After(metaInfo.ModTime()) {
			return nil, false // sidecar predates the latest scan.json → rebuild
		}
	}
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, false
	}
	var rec ScanRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, false
	}
	return &rec, true
}

// readScanSummary parses a scan.json into a ScanRecord WITHOUT its event log,
// streaming past the events array so a huge log is never read into memory. This
// is the events-free parse behind the summary cache; it replaces the old
// os.ReadFile + Unmarshal(scanRecordLite) path that copied the entire events
// blob into a RawMessage only to discard it.
func readScanSummary(path string) (*ScanRecord, bool) {
	meta, _, err := walkScanJSON(path, nil)
	if err != nil {
		return nil, false
	}
	rec, err := recordFromMeta(meta)
	if err != nil {
		return nil, false
	}
	rec.Events = nil
	return rec, true
}

// loadScanRecordForDetail loads a scan record for the detail response with only
// the last `tail` events inline. It sets EventsTotal and, when older events
// were dropped, EventsTruncated. Falls back to a full load on any streaming
// error so callers still get a correct (if slower) response for odd records.
func (s *Server) loadScanRecordForDetail(dir string, tail int) (*ScanRecord, bool) {
	if dir == "" {
		return nil, false
	}
	if tail < 0 {
		tail = 0
	}

	// Fast path: a current sidecar already holds metadata + the event tail, so
	// serve it without touching the (possibly huge) scan.json at all.
	if meta, ok := readScanDetailMeta(dir); ok {
		return meta, true
	}

	path := filepath.Join(dir, "scan.json")

	// Ring buffer keeping only the last `tail` raw events.
	ring := make([]json.RawMessage, 0, tail)
	meta, total, err := walkScanJSON(path, func(_ int, raw json.RawMessage) {
		if tail == 0 {
			return
		}
		if len(ring) < tail {
			ring = append(ring, raw)
			return
		}
		copy(ring, ring[1:])
		ring[tail-1] = raw
	})
	if err != nil {
		// Fallback: legacy/edge records that don't stream cleanly.
		return loadScanRecordFromDir(dir)
	}
	rec, err := recordFromMeta(meta)
	if err != nil {
		return loadScanRecordFromDir(dir)
	}
	rec.Events = decodeEvents(ring)
	if rec.EventsJournal {
		rec.Events = nil
		var journalErr error
		total, _, journalErr = walkEventJournal(dir, func(_ int, event WSEvent) {
			if tail > 0 {
				if len(rec.Events) >= tail {
					copy(rec.Events, rec.Events[1:])
					rec.Events = rec.Events[:tail-1]
				}
				rec.Events = append(rec.Events, event)
			}
		})
		if journalErr != nil {
			return nil, false
		}
	}
	rec.EventsTotal = total
	rec.EventsTruncated = total > len(rec.Events)

	// Lazily persist the sidecar so the next open of this (immutable, terminal)
	// scan is instant. Running scans get a fresh sidecar from saveScanRecordTo
	// on every save, so only backfill terminal ones here.
	if isTerminalDetailStatus(rec.Status) {
		writeScanDetailMetaLight(dir, rec)
	}
	return rec, true
}

// isTerminalDetailStatus reports whether a scan will no longer change on disk,
// making its detail sidecar safe to cache indefinitely.
func isTerminalDetailStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "completed", "stopped", "failed":
		return true
	default:
		return false
	}
}

// loadScanEventsWindow returns the events in [offset, offset+limit) in original
// order, plus the total event count. Used by the lazy-paging endpoint.
func loadScanEventsWindow(dir string, offset, limit int) ([]WSEvent, int, bool) {
	if dir == "" || limit <= 0 {
		return nil, 0, false
	}
	if offset < 0 {
		offset = 0
	}
	if limit > maxEventsWindow {
		limit = maxEventsWindow
	}
	path := filepath.Join(dir, "scan.json")
	end := offset + limit
	if rec, ok := readScanSummary(path); ok && rec.EventsJournal {
		window := make([]WSEvent, 0, limit)
		total, _, err := walkEventJournal(dir, func(idx int, event WSEvent) {
			if idx >= offset && idx < end {
				window = append(window, event)
			}
		})
		return window, total, err == nil
	}
	window := make([]json.RawMessage, 0, limit)
	_, total, err := walkScanJSON(path, func(idx int, raw json.RawMessage) {
		if idx >= offset && idx < end {
			window = append(window, raw)
		}
	})
	if err != nil {
		return nil, 0, false
	}
	return decodeEvents(window), total, true
}
