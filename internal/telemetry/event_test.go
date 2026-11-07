package telemetry

import (
	"encoding/binary"
	"testing"
)

func TestDecodeRawExecEvent(t *testing.T) {
	buf := make([]byte, RawExecEventSize)

	binary.LittleEndian.PutUint64(buf[0:8], 123456789)
	binary.LittleEndian.PutUint64(buf[8:16], 42)
	binary.LittleEndian.PutUint64(buf[16:24], 1001)

	binary.LittleEndian.PutUint32(buf[24:28], 10)
	binary.LittleEndian.PutUint32(buf[28:32], 20)
	binary.LittleEndian.PutUint32(buf[32:36], 1000)
	binary.LittleEndian.PutUint32(buf[36:40], 1000)

	copy(buf[40:56], "sh\x00")
	copy(buf[56:312], "/bin/sh\x00")

	var raw RawExecEvent
	err := DecodeRawExecEvent(buf, &raw)
	if err != nil {
		t.Fatalf("unexpected error decoding: %v", err)
	}

	if raw.TimestampNS != 123456789 {
		t.Errorf("expected TimestampNS=123456789, got %d", raw.TimestampNS)
	}
	if raw.CgroupID != 42 {
		t.Errorf("expected CgroupID=42, got %d", raw.CgroupID)
	}
	if raw.SeqNum != 1001 {
		t.Errorf("expected SeqNum=1001, got %d", raw.SeqNum)
	}
	if raw.TID != 10 || raw.TGID != 20 {
		t.Errorf("expected TID=10, TGID=20; got TID=%d, TGID=%d", raw.TID, raw.TGID)
	}

	ev := NewSecurityEvent(raw)
	if ev.Comm != "sh" {
		t.Errorf("expected comm 'sh', got '%s'", ev.Comm)
	}
	if ev.Filename != "/bin/sh" {
		t.Errorf("expected filename '/bin/sh', got '%s'", ev.Filename)
	}
	if ev.State != AttributionPending {
		t.Errorf("expected initial state PENDING, got %s", ev.State)
	}
}

func TestTelemetryAccounting(t *testing.T) {
	acc := &TelemetryAccounting{}

	acc.KernelHookInvocations.Store(100)
	acc.KernelRingBufferDrops.Store(5)
	acc.KernelRingBufferSubmit.Store(95)
	acc.RecordsReceived.Store(95)
	acc.RecordsDecoded.Store(95)
	acc.AttributionResolved.Store(90)
	acc.AttributionUnresolved.Store(5)

	snap := acc.Snapshot()
	if snap.KernelHookInvocations != 100 {
		t.Errorf("expected 100 hook invocations, got %d", snap.KernelHookInvocations)
	}
	if snap.KernelDropRatePercent != 5.0 {
		t.Errorf("expected 5.0%% drop rate, got %f", snap.KernelDropRatePercent)
	}
	if snap.UserspaceLossCount != 0 {
		t.Errorf("expected 0 loss count, got %d", snap.UserspaceLossCount)
	}
}
