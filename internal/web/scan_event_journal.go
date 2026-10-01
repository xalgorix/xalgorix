package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const scanEventJournalFile = "events.jsonl"

// A partial final line is an interrupted append, never a completed event.
// The returned boundary permits recovery without discarding valid history.
func walkEventJournal(dir string, onEvent func(int, WSEvent)) (int, int64, error) {
	f, err := os.Open(filepath.Join(dir, scanEventJournalFile))
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	total := 0
	var boundary int64
	for {
		line, err := reader.ReadBytes('\n')
		if err == io.EOF {
			return total, boundary, nil
		}
		if err != nil {
			return total, boundary, err
		}
		var event WSEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return total, boundary, fmt.Errorf("invalid event journal entry %d: %w", total, err)
		}
		if onEvent != nil {
			onEvent(total, event)
		}
		total++
		boundary += int64(len(line))
	}
}

func appendEventTail(events []WSEvent, event WSEvent) []WSEvent {
	if len(events) < detailEventTail {
		return append(events, event)
	}
	copy(events, events[len(events)-detailEventTail+1:])
	events = events[:detailEventTail]
	events[detailEventTail-1] = event
	return events
}

// Migrate legacy embedded history once using bounded memory. scan.json keeps
// its old data until the journal is durable and the new metadata is saved.
func prepareScanEventJournal(dir string, rec *ScanRecord, reset bool) error {
	tail := make([]WSEvent, 0, detailEventTail)
	if rec.EventsJournal && !reset {
		total, boundary, err := walkEventJournal(dir, func(_ int, event WSEvent) { tail = appendEventTail(tail, event) })
		if err != nil {
			return err
		}
		if err := os.Truncate(filepath.Join(dir, scanEventJournalFile), boundary); err != nil {
			return err
		}
		rec.Events, rec.EventsTotal = tail, total
		rec.EventsTruncated = total > len(tail)
		return nil
	}
	f, err := os.CreateTemp(dir, ".events-*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	defer f.Close()
	encoder := json.NewEncoder(f)
	total := 0
	var writeErr error
	writeEvent := func(event WSEvent) {
		if writeErr != nil {
			return
		}
		total++
		if event.EventID == "" {
			event.EventID = fmt.Sprintf("%s:%d", rec.ID, total)
		}
		writeErr = encoder.Encode(event)
		tail = appendEventTail(tail, event)
	}
	legacy := filepath.Join(dir, "scan.json")
	if _, err := os.Stat(legacy); err == nil && !reset {
		_, _, err = walkScanJSON(legacy, func(_ int, raw json.RawMessage) {
			if writeErr != nil {
				return
			}
			var event WSEvent
			if writeErr = json.Unmarshal(raw, &event); writeErr == nil {
				writeEvent(event)
			}
		})
		if err != nil {
			return err
		}
	} else {
		for _, event := range rec.Events {
			writeEvent(event)
		}
	}
	if writeErr != nil {
		return writeErr
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(dir, scanEventJournalFile)); err != nil {
		return err
	}
	rec.EventsJournal = true
	rec.Events, rec.EventsTotal = tail, total
	rec.EventsTruncated = total > len(tail)
	return nil
}

func appendScanEventJournal(dir string, event WSEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, scanEventJournalFile), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
