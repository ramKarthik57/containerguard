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
	binary.LittleEndian.PutUint64(buf[24:32], 500000) // StartTimeNS
	binary.LittleEndian.PutUint64(buf[32:40], 400000) // ParentStartTimeNS

	binary.LittleEndian.PutUint32(buf[40:44], 10)   // TID
	binary.LittleEndian.PutUint32(buf[44:48], 20)   // TGID
	binary.LittleEndian.PutUint32(buf[48:52], 1)    // ParentTGID
	binary.LittleEndian.PutUint32(buf[52:56], 1000) // UID
	binary.LittleEndian.PutUint32(buf[56:60], 1000) // GID
	binary.LittleEndian.PutUint32(buf[60:64], 0)    // Pad

	copy(buf[64:80], "sh\x00")
	copy(buf[80:336], "/bin/sh\x00")

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
	if raw.StartTimeNS != 500000 {
		t.Errorf("expected StartTimeNS=500000, got %d", raw.StartTimeNS)
	}
	if raw.ParentStartTimeNS != 400000 {
		t.Errorf("expected ParentStartTimeNS=400000, got %d", raw.ParentStartTimeNS)
	}
	if raw.ParentTGID != 1 {
		t.Errorf("expected ParentTGID=1, got %d", raw.ParentTGID)
	}

	ev := NewSecurityEvent(raw)
	if ev.Comm != "sh" {
		t.Errorf("expected comm 'sh', got '%s'", ev.Comm)
	}
	if ev.Filename != "/bin/sh" {
		t.Errorf("expected filename '/bin/sh', got '%s'", ev.Filename)
	}
	if ev.Key.StartTimeNS != 500000 || ev.Key.TGID != 20 || ev.Key.CgroupID != 42 {
		t.Errorf("structured key mismatch: %+v", ev.Key)
	}
	if ev.ParentKey.StartTimeNS != 400000 || ev.ParentKey.TGID != 1 {
		t.Errorf("structured parent key mismatch: %+v", ev.ParentKey)
	}
}

func TestSequenceTrackerReorderingAndGaps(t *testing.T) {
	st := NewSequenceTracker(100)

	// Seq 1 arrives
	reordered, gap := st.Observe(1)
	if reordered || gap != 0 {
		t.Errorf("expected initial seq normal, got reordered=%v, gap=%d", reordered, gap)
	}

	// Seq 3 arrives (Seq 2 jumped, potential gap of 1)
	reordered, gap = st.Observe(3)
	if reordered || gap != 1 {
		t.Errorf("expected gap=1, got reordered=%v, gap=%d", reordered, gap)
	}

	// Seq 2 arrives late (out of order arrival across cores)
	reordered, gap = st.Observe(2)
	if !reordered || gap != 0 {
		t.Errorf("expected reordered=true, gap=0; got reordered=%v, gap=%d", reordered, gap)
	}
}
