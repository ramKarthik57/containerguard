package lineage

import (
	"testing"
	"time"

	"cg-smoke-test/internal/telemetry"
)

func TestLineageTrackerPIDReuseAndIsolation(t *testing.T) {
	tracker := NewLineageTracker(100, 1*time.Minute)

	// Container 1 (cgroup 100) running TGID 42
	ev1 := &telemetry.SecurityEvent{
		CgroupID:    100,
		TGID:        42,
		TID:         42,
		Comm:        "app1",
		Filename:    "/bin/app1",
		CapturedAt:  time.Now(),
		ContainerID: "cont-1",
	}
	n1 := tracker.RecordExec(ev1)

	// Container 2 (cgroup 200) also running TGID 42 (PID reuse across containers)
	ev2 := &telemetry.SecurityEvent{
		CgroupID:    200,
		TGID:        42,
		TID:         42,
		Comm:        "app2",
		Filename:    "/bin/app2",
		CapturedAt:  time.Now(),
		ContainerID: "cont-2",
	}
	n2 := tracker.RecordExec(ev2)

	// Verify both nodes exist independently without collision
	retrieved1, ok1 := tracker.GetProcess(100, 42)
	if !ok1 || retrieved1.Executable != "/bin/app1" {
		t.Errorf("expected /bin/app1 for cgroup 100, got %v", retrieved1)
	}

	retrieved2, ok2 := tracker.GetProcess(200, 42)
	if !ok2 || retrieved2.Executable != "/bin/app2" {
		t.Errorf("expected /bin/app2 for cgroup 200, got %v", retrieved2)
	}

	if n1.CompositeKey == n2.CompositeKey {
		t.Errorf("composite keys collided for distinct cgroups: %d", n1.CompositeKey)
	}
}
