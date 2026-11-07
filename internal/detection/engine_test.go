package detection

import (
	"testing"
	"time"

	"cg-smoke-test/internal/lineage"
	"cg-smoke-test/internal/telemetry"
)

func TestDetectionRules(t *testing.T) {
	tracker := lineage.NewLineageTracker(100, 1*time.Minute)
	engine := NewEngine(tracker)

	// 1. Host confirmed event executing nsenter should NOT trigger container breakout alert
	hostEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionHostConfirmed,
		Filename:      "/usr/bin/nsenter",
		Comm:          "nsenter",
		SeqNum:        1,
		CapturedAt:    time.Now(),
		ContainerID:   "host",
		ContainerName: "HOST",
	}
	alerts := engine.Evaluate(hostEv)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for host event, got %d", len(alerts))
	}

	// 2. Container event executing nsenter SHOULD trigger CRITICAL alert
	contEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		Filename:      "/usr/bin/nsenter",
		Comm:          "nsenter",
		SeqNum:        2,
		CapturedAt:    time.Now(),
		CgroupID:      400,
		TGID:          1234,
		ContainerID:   "cont-target",
		ContainerName: "target-container",
	}
	tracker.RecordExec(contEv)
	alerts = engine.Evaluate(contEv)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for container nsenter, got %d", len(alerts))
	}
	if alerts[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", alerts[0].Severity)
	}

	// 3. Container executing script from /tmp
	tmpEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		Filename:      "/tmp/exploit.sh",
		Comm:          "exploit.sh",
		SeqNum:        3,
		CapturedAt:    time.Now(),
		ContainerID:   "cont-target",
		ContainerName: "target-container",
	}
	alerts = engine.Evaluate(tmpEv)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for /tmp execution, got %d", len(alerts))
	}
	if alerts[0].RuleID != "CG-RULE-002" {
		t.Errorf("expected rule CG-RULE-002, got %s", alerts[0].RuleID)
	}
}
