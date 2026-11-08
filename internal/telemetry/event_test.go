package telemetry

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

func TestDecodeRawExecEventWithLeaderAndFlags(t *testing.T) {
	buf := make([]byte, RawExecEventSize)

	binary.LittleEndian.PutUint64(buf[0:8], 123456789) // TimestampNS
	binary.LittleEndian.PutUint64(buf[8:16], 42)       // CgroupID
	binary.LittleEndian.PutUint64(buf[16:24], 88)      // ParentCgroupID
	binary.LittleEndian.PutUint64(buf[24:32], 1001)    // SeqNum
	binary.LittleEndian.PutUint64(buf[32:40], 500000)  // StartTimeNS (leader)
	binary.LittleEndian.PutUint64(buf[40:48], 400000)  // ParentStartTimeNS (parent leader)

	binary.LittleEndian.PutUint32(buf[48:52], 105)                                                   // TID (worker subthread calling execve)
	binary.LittleEndian.PutUint32(buf[52:56], 100)                                                   // TGID (thread-group leader process ID)
	binary.LittleEndian.PutUint32(buf[56:60], 1)                                                     // ParentTGID
	binary.LittleEndian.PutUint32(buf[60:64], 1000)                                                  // UID
	binary.LittleEndian.PutUint32(buf[64:68], 1000)                                                  // GID
	binary.LittleEndian.PutUint32(buf[68:72], FlagStartTimeEstimated|FlagExecveat|FlagCommittedExec) // Flags

	binary.LittleEndian.PutUint32(buf[72:76], uint32(5)) // Dfd
	binary.LittleEndian.PutUint32(buf[76:80], 0x1000)    // AtFlags (AT_EMPTY_PATH)
	binary.LittleEndian.PutUint32(buf[80:84], 0)         // ExitCode
	binary.LittleEndian.PutUint32(buf[84:88], 0)         // Pad

	copy(buf[88:104], "worker_thread\x00")
	copy(buf[104:360], "/usr/local/bin/worker\x00")

	var raw RawExecEvent
	err := DecodeRawExecEvent(buf, &raw)
	if err != nil {
		t.Fatalf("unexpected error decoding: %v", err)
	}

	if raw.TID != 105 || raw.TGID != 100 {
		t.Errorf("expected TID=105, TGID=100; got TID=%d, TGID=%d", raw.TID, raw.TGID)
	}
	if raw.StartTimeNS != 500000 {
		t.Errorf("expected leader StartTimeNS=500000, got %d", raw.StartTimeNS)
	}
	if raw.ParentCgroupID != 88 {
		t.Errorf("expected ParentCgroupID=88, got %d", raw.ParentCgroupID)
	}
	if raw.Dfd != 5 {
		t.Errorf("expected Dfd=5, got %d", raw.Dfd)
	}

	ev := NewSecurityEvent(raw)
	if !ev.StartTimeEstimated {
		t.Errorf("expected StartTimeEstimated to be true from flags")
	}
	if !ev.Execveat || !ev.Committed {
		t.Errorf("expected Execveat and Committed to be true from flags")
	}
	if ev.Key.TGID != 100 || ev.Key.StartTimeNS != 500000 {
		t.Errorf("process key should reflect process-level identity: %+v", ev.Key)
	}
	if ev.ParentKey.CgroupID != 88 {
		t.Errorf("parent key should use independently resolved ParentCgroupID 88, got %d", ev.ParentKey.CgroupID)
	}
	if ev.TID != 105 {
		t.Errorf("executing subthread TID should be preserved: %d", ev.TID)
	}
}

func TestProcessIdentityDecoupling(t *testing.T) {
	key1 := ProcessKey{CgroupID: 100, TGID: 555, StartTimeNS: 12345}
	key2 := ProcessKey{CgroupID: 200, TGID: 555, StartTimeNS: 12345} // Migrated cgroup

	// Immutable identity is identical across cgroup migrations
	if key1.InstanceKey() != key2.InstanceKey() {
		t.Errorf("InstanceKey must be invariant across cgroups: %v != %v", key1.InstanceKey(), key2.InstanceKey())
	}
}

func TestSequenceTrackerWatermarkAndReordering(t *testing.T) {
	window := uint64(5)
	st := NewSequenceTracker(window)

	// Step 1: Initialize at seq 10
	reordered, loss := st.Observe(10)
	if reordered || loss != 0 {
		t.Errorf("expected init seq=10 normal")
	}

	// Step 2: Receive seq 12 (seq 11 is now in pendingGaps, not immediately declared lost!)
	reordered, loss = st.Observe(12)
	if reordered || loss != 0 {
		t.Errorf("expected seq=12 not to declare immediate loss, got loss=%d", loss)
	}
	_, _, pending := st.Stats()
	if pending != 1 {
		t.Errorf("expected 1 pending gap for seq=11, got %d", pending)
	}

	// Step 3: Seq 11 arrives slightly delayed -> resolves pending gap without loss!
	reordered, loss = st.Observe(11)
	if !reordered || loss != 0 {
		t.Errorf("expected reordered=true for delayed seq=11, got reordered=%v, loss=%d", reordered, loss)
	}
	_, _, pending = st.Stats()
	if pending != 0 {
		t.Errorf("expected 0 pending gaps after out-of-order resolution, got %d", pending)
	}

	// Step 4: True loss scenario: seq jumps from 12 to 20 (gaps: 13, 14, 15, 16, 17, 18, 19)
	reordered, loss = st.Observe(20)
	// Watermark is 20 - 5 = 15. Any pending gaps <= 15 (i.e. 13, 14, 15) are now retired as confirmed loss!
	if loss != 3 {
		t.Errorf("expected 3 confirmed losses past watermark (13,14,15), got %d", loss)
	}

	// Step 5: Flush remaining gaps on shutdown
	flushed := st.FlushRetires()
	if flushed != 4 { // 16, 17, 18, 19
		t.Errorf("expected 4 remaining gaps flushed on shutdown, got %d", flushed)
	}
}

func TestConcurrentSequenceStress(t *testing.T) {
	st := NewSequenceTracker(500)
	const count = 1000

	seqs := make([]uint64, count)
	for i := 0; i < count; i++ {
		seqs[i] = uint64(i + 1)
	}

	// Shuffle adjacent pairs to simulate out-of-order multi-core ring buffer delivery
	r := rand.New(rand.NewSource(42))
	for i := 0; i < count-1; i += 2 {
		if r.Float32() > 0.5 {
			seqs[i], seqs[i+1] = seqs[i+1], seqs[i]
		}
	}

	var totalLoss uint64
	for _, s := range seqs {
		_, loss := st.Observe(s)
		totalLoss += loss
	}
	totalLoss += st.FlushRetires()

	if totalLoss != 0 {
		t.Errorf("expected 0 losses in clean reordered stream, got %d", totalLoss)
	}

	reordered, _, _ := st.Stats()
	if reordered == 0 {
		t.Errorf("expected non-zero reordered events detected, got %d", reordered)
	}
}
