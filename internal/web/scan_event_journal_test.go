package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestEventJournalMigrationPaginationAndInterruptedAppend(t *testing.T) {
	dir := t.TempDir()
	rec := &ScanRecord{ID: "history", Status: "running"}
	for i := 0; i < 850; i++ {
		rec.Events = append(rec.Events, WSEvent{Type: "message", Content: fmt.Sprintf("event-%d", i)})
	}
	s := &Server{}
	s.saveScanRecordTo(rec, dir)
	if err := prepareScanEventJournal(dir, rec, false); err != nil {
		t.Fatal(err)
	}
	if len(rec.Events) != detailEventTail || rec.EventsTotal != 850 || rec.Events[0].Content != "event-550" {
		t.Fatal("migration did not retain a bounded, correct tail")
	}
	event := WSEvent{EventID: "history:851", Type: "message", Content: "event-850"}
	if err := appendScanEventJournal(dir, event); err != nil {
		t.Fatal(err)
	}
	rec.EventsTotal++
	rec.Events = appendEventTail(rec.Events, event)
	s.saveScanRecordTo(rec, dir)
	data, err := os.ReadFile(filepath.Join(dir, "scan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata ScanRecord
	if err := json.Unmarshal(data, &metadata); err != nil || len(metadata.Events) != detailEventTail {
		t.Fatal("metadata rewrote the full growing event history")
	}
	window, total, ok := loadScanEventsWindow(dir, 848, 10)
	if !ok || total != 851 || len(window) != 3 || window[2].EventID != "history:851" {
		t.Fatalf("journal pagination lost order or stable IDs: %t %d %+v", ok, total, window)
	}
	full, ok := loadScanRecordFromDir(dir)
	if !ok || len(full.Events) != 851 || full.Events[0].Content != "event-0" {
		t.Fatal("full-history consumers lost legacy events")
	}
	f, err := os.OpenFile(filepath.Join(dir, scanEventJournalFile), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"type":"unfinished`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := prepareScanEventJournal(dir, rec, false); err != nil {
		t.Fatal(err)
	}
	if err := appendScanEventJournal(dir, WSEvent{EventID: "history:852", Content: "continued"}); err != nil {
		t.Fatal(err)
	}
	window, total, ok = loadScanEventsWindow(dir, 850, 10)
	if !ok || total != 852 || len(window) != 2 || window[1].Content != "continued" {
		t.Fatal("recovery discarded valid history or left a torn append")
	}
}
