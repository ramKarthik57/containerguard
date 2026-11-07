package pipeline

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"cg-smoke-test/internal/container"
	"cg-smoke-test/internal/telemetry"
)

func TestAttributionRaceResolution(t *testing.T) {
	resolver := container.NewContainerResolver(nil)
	resolver.SetHostRootCgroup(9999)

	accounting := &telemetry.TelemetryAccounting{}
	cfg := Config{
		MaxPendingCapacity: 100,
		PendingTTL:         1 * time.Second,
		ReconcileInterval:  20 * time.Millisecond,
		OutputChannelSize:  100,
	}

	buffer := NewAttributionBuffer(cfg, resolver, accounting)
	ingester := NewIngester(buffer, accounting)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go buffer.Run(ctx)

	// Step 1: Simulate eBPF event arriving BEFORE container registration (cgroup 500)
	rawSample := make([]byte, telemetry.RawExecEventSize)
	binary.LittleEndian.PutUint64(rawSample[0:8], 1000)
	binary.LittleEndian.PutUint64(rawSample[8:16], 500)  // CgroupID = 500
	binary.LittleEndian.PutUint64(rawSample[16:24], 1)   // Seq = 1
	binary.LittleEndian.PutUint32(rawSample[24:28], 100) // TID
	binary.LittleEndian.PutUint32(rawSample[28:32], 100) // TGID
	copy(rawSample[40:56], "app\x00")
	copy(rawSample[56:312], "/usr/local/bin/app\x00")

	ev, err := ingester.ProcessRawSample(ctx, rawSample)
	if err != nil {
		t.Fatalf("failed to process raw sample: %v", err)
	}
	if ev.State != telemetry.AttributionPending {
		t.Errorf("expected initial state PENDING, got %s", ev.State)
	}

	// Verify nothing was emitted prematurely
	select {
	case <-buffer.Output():
		t.Fatal("unexpected event emitted while still pending")
	case <-time.After(50 * time.Millisecond):
	}

	// Step 2: Simulate Docker container "start" lifecycle event occurring 100ms later
	cInfo := container.ContainerInfo{
		ID:         "cont-500-hash",
		Name:       "victim-container",
		Image:      "ubuntu:24.04",
		InitPID:    100,
		CgroupPath: "/docker/cont-500-hash",
		CgroupID:   500,
	}
	resolver.RegisterDirect(cInfo)

	// Step 3: Verify the pending event was immediately resolved and emitted with container identity
	select {
	case resolvedEv := <-buffer.Output():
		if resolvedEv.State != telemetry.AttributionResolved {
			t.Errorf("expected state RESOLVED, got %s", resolvedEv.State)
		}
		if resolvedEv.ContainerName != "victim-container" {
			t.Errorf("expected ContainerName 'victim-container', got '%s'", resolvedEv.ContainerName)
		}
		if resolvedEv.CgroupID != 500 {
			t.Errorf("expected CgroupID 500, got %d", resolvedEv.CgroupID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for resolved event after container registration")
	}

	// Check accounting
	snap := accounting.Snapshot()
	if snap.AttributionResolved != 1 {
		t.Errorf("expected AttributionResolved=1, got %d", snap.AttributionResolved)
	}
}

func TestAttributionTTLExpiration(t *testing.T) {
	resolver := container.NewContainerResolver(nil)
	resolver.SetHostRootCgroup(9999)

	accounting := &telemetry.TelemetryAccounting{}
	cfg := Config{
		MaxPendingCapacity: 100,
		PendingTTL:         50 * time.Millisecond, // Fast expiration
		ReconcileInterval:  10 * time.Millisecond,
		OutputChannelSize:  100,
	}

	buffer := NewAttributionBuffer(cfg, resolver, accounting)
	ingester := NewIngester(buffer, accounting)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go buffer.Run(ctx)

	// Ingest an event with unmapped cgroup 777
	rawSample := make([]byte, telemetry.RawExecEventSize)
	binary.LittleEndian.PutUint64(rawSample[0:8], 2000)
	binary.LittleEndian.PutUint64(rawSample[8:16], 777)
	binary.LittleEndian.PutUint64(rawSample[16:24], 2)

	_, err := ingester.ProcessRawSample(ctx, rawSample)
	if err != nil {
		t.Fatalf("ingest error: %v", err)
	}

	// Wait for TTL expiration
	select {
	case ev := <-buffer.Output():
		if ev.State != telemetry.AttributionUnresolved {
			t.Errorf("expected state UNRESOLVED upon timeout, got %s", ev.State)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timeout waiting for expired unresolved event")
	}

	snap := accounting.Snapshot()
	if snap.AttributionUnresolved != 1 {
		t.Errorf("expected AttributionUnresolved=1, got %d", snap.AttributionUnresolved)
	}
}

func TestSequenceGapDetection(t *testing.T) {
	resolver := container.NewContainerResolver(nil)
	resolver.SetHostRootCgroup(1)

	accounting := &telemetry.TelemetryAccounting{}
	cfg := DefaultConfig()
	buffer := NewAttributionBuffer(cfg, resolver, accounting)
	ingester := NewIngester(buffer, accounting)

	ctx := context.Background()

	// Sample 1: Seq = 10
	s1 := make([]byte, telemetry.RawExecEventSize)
	binary.LittleEndian.PutUint64(s1[8:16], 1)
	binary.LittleEndian.PutUint64(s1[16:24], 10)
	ingester.ProcessRawSample(ctx, s1)

	// Sample 2: Seq = 15 (5 events dropped in kernel ring buffer!)
	s2 := make([]byte, telemetry.RawExecEventSize)
	binary.LittleEndian.PutUint64(s2[8:16], 1)
	binary.LittleEndian.PutUint64(s2[16:24], 15)
	ingester.ProcessRawSample(ctx, s2)

	snap := accounting.Snapshot()
	if snap.SequenceGapsDetected != 4 { // missed 11, 12, 13, 14
		t.Errorf("expected 4 sequence gaps detected, got %d", snap.SequenceGapsDetected)
	}
}
