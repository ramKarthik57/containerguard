package storage

import (
	"path/filepath"
	"testing"
	"time"

	"cg-smoke-test/internal/detection"
	"cg-smoke-test/internal/mitigation"
	"cg-smoke-test/internal/telemetry"
)

func TestSQLiteStorage(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "evidence.db")

	store, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}
	defer store.Close()

	// 1. Write Events
	ev1 := &telemetry.SecurityEvent{
		SeqNum:        1,
		KernelTimeNS:  1000000,
		CapturedAt:    time.Now(),
		CgroupID:      400,
		ContainerID:   "cont-a",
		ContainerName: "webapp",
		TGID:          1234,
		StartTimeNS:   500000,
		Comm:          "ls",
		Filename:      "/bin/ls",
		State:         telemetry.AttributionResolved,
	}

	ev2 := &telemetry.SecurityEvent{
		SeqNum:        2,
		KernelTimeNS:  2000000,
		CapturedAt:    time.Now(),
		CgroupID:      400,
		ContainerID:   "cont-a",
		ContainerName: "webapp",
		TGID:          1235,
		StartTimeNS:   600000,
		Comm:          "cat",
		Filename:      "/bin/cat",
		State:         telemetry.AttributionResolved,
	}

	if err := store.WriteEvent(ev1); err != nil {
		t.Fatalf("WriteEvent ev1 failed: %v", err)
	}
	if err := store.WriteEvent(ev2); err != nil {
		t.Fatalf("WriteEvent ev2 failed: %v", err)
	}

	// 2. Query Events
	events, err := store.QueryEventsByContainer("cont-a", 10)
	if err != nil {
		t.Fatalf("QueryEventsByContainer failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(events))
	}
	if events[0].Filename != "/bin/ls" || events[1].Filename != "/bin/cat" {
		t.Errorf("Unexpected event filenames: %s, %s", events[0].Filename, events[1].Filename)
	}

	// 3. Write Alert
	al := &detection.Alert{
		ID:               "ALERT-1",
		RuleID:           "CG-RULE-001",
		Title:            "Breakout Detected",
		Severity:         detection.SeverityCritical,
		MitigationAction: "kill",
		Timestamp:        time.Now(),
		Event:            ev1,
	}
	if err := store.WriteAlert(al); err != nil {
		t.Fatalf("WriteAlert failed: %v", err)
	}

	alerts, err := store.QueryAlertsBySeverity("CRITICAL", 5)
	if err != nil {
		t.Fatalf("QueryAlertsBySeverity failed: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("Expected 1 critical alert, got %d", len(alerts))
	}
	if alerts[0].RuleID != "CG-RULE-001" {
		t.Errorf("Expected rule CG-RULE-001, got %s", alerts[0].RuleID)
	}

	// 4. Write Mitigation
	rec := &mitigation.Record{
		ID:            "MIT-1",
		AlertID:       "ALERT-1",
		RuleID:        "CG-RULE-001",
		ActionTaken:   mitigation.ActionKill,
		Mode:          "enforce",
		ContainerID:   "cont-a",
		ContainerName: "webapp",
		TGID:          1234,
		Success:       true,
		Message:       "SIGKILL sent successfully",
		Timestamp:     time.Now(),
	}
	if err := store.WriteMitigation(rec); err != nil {
		t.Fatalf("WriteMitigation failed: %v", err)
	}
}
