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
	binary.LittleEndian.PutUint64(buf[16:24], 1001)    // SeqNum
	binary.LittleEndian.PutUint64(buf[24:32], 500000)  // StartTimeNS (leader)
	binary.LittleEndian.PutUint64(buf[32:40], 400000)  // ParentStartTimeNS (parent leader)

	binary.LittleEndian.PutUint32(buf[40:44], 105)                    // TID (worker subthread calling execve)
	binary.LittleEndian.PutUint32(buf[44:48], 100)                    // TGID (thread-group leader process ID)
	binary.LittleEndian.PutUint32(buf[48:52], 1)                      // ParentTGID
	binary.LittleEndian.PutUint32(buf[52:56], 1000)                   // UID
	binary.LittleEndian.PutUint32(buf[56:60], 1000)                   // GID
	binary.LittleEndian.PutUint32(buf[60:64], FlagStartTimeEstimated) // Flags

	copy(buf[64:80], "worker_thread\x00")
	copy(buf[80:336], "/usr/local/bin/worker\x00")

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

	ev := NewSecurityEvent(raw)
	if !ev.StartTimeEstimated {
		t.Errorf("expected StartTimeEstimated to be true from flags")
	}
	// The process key must use TGID (100) and leader StartTimeNS (500000), not subthread TID
	if ev.Key.TGID != 100 || ev.Key.StartTimeNS != 500000 {
		t.Errorf("process key should reflect process-level identity: %+v", ev.Key)
	}
	if ev.TID != 105 {
		t.Errorf("executing subthread TID should be preserved: %d", ev.TID)
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

	totalEvents := 2000
	seqs := make([]uint64, totalEvents)
	for i := 0; i < totalEvents; i++ {
		seqs[i] = uint64(i + 1)
	}

	// Artificially withhold 5 specific sequence numbers to create genuine losses:
	withheld := map[uint64]bool{50: true, 200: true, 555: true, 999: true, 1500: true}
	var activeSeqs []uint64
	for _, s := range seqs {
		if !withheld[s] {
			activeSeqs = append(activeSeqs, s)
		}
	}

	// Apply realistic multi-core commit jitter (+/- 16 positions)
	r := rand.New(rand.NewSource(42))
	for i := range activeSeqs {
		jitter := r.Intn(32) - 16
		target := i + jitter
		if target >= 0 && target < len(activeSeqs) {
			activeSeqs[i], activeSeqs[target] = activeSeqs[target], activeSeqs[i]
		}
	}

	// Ingest the jittered stream (as delivered by the kernel ring buffer epoll loop)
	for _, s := range activeSeqs {
		st.Observe(s)
	}

	flushed := st.FlushRetires()

	reordered, confirmed, _ := st.Stats()
	totalLost := confirmed + flushed

	if totalLost != uint64(len(withheld)) {
		t.Errorf("expected exactly %d confirmed losses from withheld seqs, got %d (confirmed=%d, flushed=%d, reordered=%d)",
			len(withheld), totalLost, confirmed, flushed, reordered)
	}
}
