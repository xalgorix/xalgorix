package web

import (
	"reflect"
	"testing"
)

func TestResumeKeepsKnownSessionProgressLowerBound(t *testing.T) {
	for _, aggregate := range []int{10, 50} {
		s := newTestServer(t, nil)
		record := &ScanRecord{
			ID: "parent", InstanceID: "coordinator", Target: "example.invalid", ScanMode: "wildcard", Status: "running",
			StartedAt: "2026-01-01T00:00:00Z", AssessmentProgress: aggregate, TotalTokens: 100,
			UsageBySession: map[string]sessionUsage{"discovery": {Tokens: 40, Progress: 6}, "child": {Tokens: 60, Progress: 9}},
		}
		directory := s.makeScanDir("parent")
		s.saveScanRecordTo(record, directory)
		instance := &ScanInstance{ID: "coordinator", TotalTokens: 100}
		s.seedResumeInstanceFromRecord(instance, ScanRequest{IsResume: true, ResumeScanDir: directory})
		want := max(aggregate, 15)
		if instance.AssessmentProgress != want || instance.TotalTokens != 100 || instance.StartedAt != record.StartedAt || !reflect.DeepEqual(instance.UsageBySession, record.UsageBySession) {
			t.Fatalf("restore dropped known progress or changed clocks/usage: aggregate=%d, instance=%+v", aggregate, instance)
		}
		s.seedResumeInstanceFromRecord(instance, ScanRequest{IsResume: true, ResumeScanDir: directory})
		if instance.AssessmentProgress != want {
			t.Fatal("repeated restore counted the same facts again")
		}
	}
}

func TestResumeCombinesOwnedSessionHighWaterMarks(t *testing.T) {
	s := newTestServer(t, nil)
	record := &ScanRecord{
		ID: "parent", InstanceID: "coordinator", Target: "example.invalid", ScanMode: "wildcard", Status: "running",
		AssessmentProgress: 10, UsageBySession: map[string]sessionUsage{"discovery": {Progress: 6}, "child": {Progress: 9}},
	}
	directory := s.makeScanDir("parent")
	s.saveScanRecordTo(record, directory)
	instance := &ScanInstance{
		ID: "coordinator", AssessmentProgress: 12,
		UsageBySession: map[string]sessionUsage{"child": {Progress: 14}, "earlier": {Progress: 2}},
	}
	s.seedResumeInstanceFromRecord(instance, ScanRequest{IsResume: true, ResumeScanDir: directory})
	if instance.AssessmentProgress != 22 || instance.UsageBySession["child"].Progress != 14 || instance.UsageBySession["earlier"].Progress != 2 {
		t.Fatalf("recovery lost a known session or regressed a high-water mark: %+v", instance)
	}
}
