package tui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"cg-smoke-test/internal/detection"
	"cg-smoke-test/internal/mitigation"
	"cg-smoke-test/internal/telemetry"
)

func TestLiveMonitorRender(t *testing.T) {
	var buf bytes.Buffer
	mon := NewLiveMonitor(&buf)

	// Record an event
	mon.RecordEvent(&telemetry.SecurityEvent{
		ContainerName: "webapp-prod",
	})

	// Record an alert
	mon.RecordAlert(&detection.Alert{
		ID:               "ALERT-001",
		RuleID:           "CG-RULE-001",
		Title:            "Breakout Detected",
		Severity:         detection.SeverityCritical,
		MitigationAction: "kill",
		Timestamp:        time.Now(),
	})

	// Record a mitigation
	mon.RecordMitigation(&mitigation.Record{
		ActionTaken:   mitigation.ActionKill,
		TGID:          1234,
		ContainerName: "webapp-prod",
		Success:       true,
		Message:       "SIGKILL sent",
		Timestamp:     time.Now(),
	})

	snap := telemetry.MetricsSnapshot{
		KernelHookInvocations:  500,
		KernelRingBufferSubmit: 450,
		KernelRingBufferDrops:  50,
		KernelDropRatePercent:  10.0,
		EventsProcessed:        450,
		SequenceGapsDetected:   0,
	}

	mon.Render(snap, "enforce")
	output := buf.String()

	if !strings.Contains(output, "ContainerGuard Enterprise v2.0") {
		t.Errorf("Missing banner header in TUI output")
	}
	if !strings.Contains(output, "SATISFIED (Hooks = Submissions + Drops)") {
		t.Errorf("Expected loss invariant SATISFIED in TUI output")
	}
	if !strings.Contains(output, "webapp-prod") {
		t.Errorf("Missing container name in TUI output")
	}
	if !strings.Contains(output, "CG-RULE-001") {
		t.Errorf("Missing alert rule in TUI output")
	}
	if !strings.Contains(output, "SIGKILL sent") {
		t.Errorf("Missing mitigation record in TUI output")
	}
}
