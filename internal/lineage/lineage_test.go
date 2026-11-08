package lineage

import (
	"strings"
	"testing"
	"time"

	"cg-smoke-test/internal/telemetry"
)

func TestLineageStructuredKeyPIDReuseAndCrossContainer(t *testing.T) {
	tracker := NewLineageTracker(100, 15*time.Minute)

	// Scenario 1: Intra-cgroup PID Reuse (same cgroup 100, same TGID 500, successive lifecycles)
	p1Key := telemetry.ProcessKey{CgroupID: 100, TGID: 500, StartTimeNS: 1000000}
	ev1 := &telemetry.SecurityEvent{
		Key:         p1Key,
		CgroupID:    100,
		TGID:        500,
		StartTimeNS: 1000000,
		Comm:        "batch_job_1",
		Filename:    "/usr/bin/job1",
		CapturedAt:  time.Now(),
	}
	tracker.RecordExec(ev1)

	p2Key := telemetry.ProcessKey{CgroupID: 100, TGID: 500, StartTimeNS: 2000000} // PID reused later
	ev2 := &telemetry.SecurityEvent{
		Key:         p2Key,
		CgroupID:    100,
		TGID:        500,
		StartTimeNS: 2000000,
		Comm:        "batch_job_2",
		Filename:    "/usr/bin/job2",
		CapturedAt:  time.Now().Add(1 * time.Second),
	}
	tracker.RecordExec(ev2)

	// Verify both process instances exist independently without overwrite
	node1, ok1 := tracker.GetProcess(p1Key)
	if !ok1 || node1.Executable != "/usr/bin/job1" {
		t.Fatalf("failed to retrieve original process instance 1: %+v", node1)
	}

	node2, ok2 := tracker.GetProcess(p2Key)
	if !ok2 || node2.Executable != "/usr/bin/job2" {
		t.Fatalf("failed to retrieve reused process instance 2: %+v", node2)
	}

	// Scenario 2: Cross-Container Isolation (cgroup 200 also has TGID 500 at StartTime 1000000)
	p3Key := telemetry.ProcessKey{CgroupID: 200, TGID: 500, StartTimeNS: 1000000}
	ev3 := &telemetry.SecurityEvent{
		Key:         p3Key,
		CgroupID:    200,
		TGID:        500,
		StartTimeNS: 1000000,
		Comm:        "other_container_app",
		Filename:    "/app/worker",
		CapturedAt:  time.Now(),
	}
	tracker.RecordExec(ev3)

	node3, ok3 := tracker.GetProcess(p3Key)
	if !ok3 || node3.Executable != "/app/worker" {
		t.Fatalf("failed to retrieve cross-container process instance: %+v", node3)
	}

	// Verify p1Key still points to /usr/bin/job1
	node1Check, _ := tracker.GetProcess(p1Key)
	if node1Check.Executable != "/usr/bin/job1" {
		t.Errorf("cross-container collision corrupted node1: %+v", node1Check)
	}
}

func TestLineageAncestryChain(t *testing.T) {
	tracker := NewLineageTracker(100, 15*time.Minute)

	// Parent: dockerd-shim (TGID: 100, StartTime: 10000)
	parentKey := telemetry.ProcessKey{CgroupID: 50, TGID: 100, StartTimeNS: 10000}
	tracker.RecordExec(&telemetry.SecurityEvent{
		Key:         parentKey,
		CgroupID:    50,
		TGID:        100,
		StartTimeNS: 10000,
		Filename:    "/usr/bin/containerd-shim",
		CapturedAt:  time.Now(),
	})

	// Child: entrypoint.sh (TGID: 200, Parent: parentKey, StartTime: 15000)
	childKey := telemetry.ProcessKey{CgroupID: 50, TGID: 200, StartTimeNS: 15000}
	tracker.RecordExec(&telemetry.SecurityEvent{
		Key:         childKey,
		ParentKey:   parentKey,
		CgroupID:    50,
		TGID:        200,
		StartTimeNS: 15000,
		Filename:    "/entrypoint.sh",
		CapturedAt:  time.Now(),
	})

	// Grandchild: python3 (TGID: 300, Parent: childKey, StartTime: 20000)
	grandchildKey := telemetry.ProcessKey{CgroupID: 50, TGID: 300, StartTimeNS: 20000}
	gcNode := tracker.RecordExec(&telemetry.SecurityEvent{
		Key:         grandchildKey,
		ParentKey:   childKey,
		CgroupID:    50,
		TGID:        300,
		StartTimeNS: 20000,
		Filename:    "/usr/bin/python3",
		CapturedAt:  time.Now(),
	})

	chain := tracker.FormatChain(gcNode)
	if !strings.Contains(chain, "/usr/bin/containerd-shim") ||
		!strings.Contains(chain, "/entrypoint.sh") ||
		!strings.Contains(chain, "/usr/bin/python3") {
		t.Errorf("lineage chain missing ancestors: %s", chain)
	}
}
