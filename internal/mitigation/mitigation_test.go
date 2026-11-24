package mitigation

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"cg-smoke-test/internal/detection"
	"cg-smoke-test/internal/policy"
	"cg-smoke-test/internal/telemetry"
)

func TestMitigationAuditMode(t *testing.T) {
	cfg := policy.MitigationConfig{
		Enabled:       true,
		Mode:          "audit",
		DefaultAction: "kill",
		Cooldown:      1 * time.Second,
	}
	engine := NewEngine(cfg)

	killed := false
	engine.SetKillFunc(func(pid int, sig syscall.Signal) error {
		killed = true
		return nil
	})

	ev := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		SeqNum:        100,
		TGID:          5555,
		ContainerID:   "cont-bad",
		ContainerName: "bad-container",
		Filename:      "/usr/bin/nsenter",
	}

	alert := &detection.Alert{
		ID:               "ALERT-100-CG-RULE-001",
		RuleID:           "CG-RULE-001",
		MitigationAction: "kill",
		Event:            ev,
	}

	rec := engine.Execute(alert)
	if rec == nil {
		t.Fatalf("expected non-nil mitigation record")
	}
	if killed {
		t.Errorf("process should NOT be killed in audit mode")
	}
	if rec.ActionTaken != ActionKill {
		t.Errorf("expected ActionKill, got %s", rec.ActionTaken)
	}
	if rec.Mode != "audit" {
		t.Errorf("expected audit mode, got %s", rec.Mode)
	}
}

func TestMitigationPIDNamespaceTranslation(t *testing.T) {
	cfg := policy.MitigationConfig{
		Enabled:       true,
		Mode:          "enforce",
		DefaultAction: "kill",
	}
	engine := NewEngine(cfg)

	tmpProc := t.TempDir()
	engine.SetProcRoot(tmpProc)

	// Mock process in child namespace: local PID 42, but root NStgid is 99999
	procDir := filepath.Join(tmpProc, "42")
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	statusContent := "Name:\tbad_tool\nNStgid:\t99999\t42\n"
	if err := os.WriteFile(filepath.Join(procDir, "status"), []byte(statusContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	var killedPIDs []int
	engine.SetKillFunc(func(pid int, sig syscall.Signal) error {
		killedPIDs = append(killedPIDs, pid)
		if pid == 99999 {
			// Simulate ESRCH when caller is in a child PID namespace
			return syscall.ESRCH
		}
		if pid == 42 {
			// Successfully killed via translated local PID
			return nil
		}
		return syscall.ESRCH
	})

	ev := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		SeqNum:        105,
		TGID:          99999, // Root TGID from eBPF
		CgroupID:      500,
		ContainerID:   "cont-ns",
		ContainerName: "ns-container",
		Filename:      "/tmp/bad_tool",
		Comm:          "bad_tool",
	}

	alert := &detection.Alert{
		ID:               "ALERT-105-CG-RULE-002",
		RuleID:           "CG-RULE-002",
		MitigationAction: "kill",
		Event:            ev,
	}

	rec := engine.Execute(alert)
	if !rec.Success {
		t.Fatalf("expected mitigation success after translation, got failure: %s", rec.Message)
	}
	if rec.LocalPID != 42 {
		t.Errorf("expected translated LocalPID 42, got %d", rec.LocalPID)
	}
	if len(killedPIDs) != 2 || killedPIDs[1] != 42 {
		t.Errorf("expected kill attempts on [99999, 42], got %v", killedPIDs)
	}
}

func TestMitigationCgroupKillEscalation(t *testing.T) {
	cfg := policy.MitigationConfig{
		Enabled:       true,
		Mode:          "enforce",
		DefaultAction: "kill",
	}
	engine := NewEngine(cfg)
	engine.SetProcRoot(t.TempDir()) // empty proc to simulate untranslatable PID

	engine.SetKillFunc(func(pid int, sig syscall.Signal) error {
		return syscall.ESRCH // always fail direct kill
	})

	cgroupKilledPath := ""
	engine.SetCgroupKillFunc(func(cgroupPath string) error {
		cgroupKilledPath = cgroupPath
		return nil
	})

	ev := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		SeqNum:        106,
		TGID:          88888,
		CgroupID:      600,
		ContainerID:   "cont-escalate",
		ContainerName: "escalate-container",
	}

	alert := &detection.Alert{
		ID:               "ALERT-106-CG-RULE-001",
		RuleID:           "CG-RULE-001",
		MitigationAction: "kill",
		Event:            ev,
	}

	rec := engine.Execute(alert)
	if !rec.Success {
		t.Fatalf("expected escalation to cgroup.kill to succeed, got %v", rec.Message)
	}
	if cgroupKilledPath == "" {
		t.Errorf("expected cgroupKillFn to be called")
	}
}

func TestMitigationHostGuardrail(t *testing.T) {
	cfg := policy.MitigationConfig{
		Enabled:       true,
		Mode:          "enforce",
		DefaultAction: "kill",
	}
	engine := NewEngine(cfg)

	killed := false
	engine.SetKillFunc(func(pid int, sig syscall.Signal) error {
		killed = true
		return nil
	})

	hostEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionHostConfirmed,
		SeqNum:        102,
		TGID:          1,
		CgroupID:      1,
		ContainerID:   "host",
		ContainerName: "HOST",
	}

	alert := &detection.Alert{
		ID:               "ALERT-102-TEST",
		RuleID:           "CG-RULE-001",
		MitigationAction: "kill",
		Event:            hostEv,
	}

	rec := engine.Execute(alert)
	if killed {
		t.Errorf("HOST process must NEVER be killed by mitigation engine!")
	}
	if rec.Success {
		t.Errorf("expected success false due to host guardrail")
	}
}
