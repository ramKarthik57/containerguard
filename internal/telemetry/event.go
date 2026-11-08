package telemetry

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AttributionState defines the lifecycle state of container event attribution.
type AttributionState string

const (
	AttributionPending       AttributionState = "PENDING"
	AttributionResolved      AttributionState = "RESOLVED"
	AttributionUnresolved    AttributionState = "UNRESOLVED"
	AttributionStaleMapping  AttributionState = "STALE_MAPPING"
	AttributionHostConfirmed AttributionState = "HOST_CONFIRMED"
)

// ProcessKey is a structured, collision-resistant process identity preventing PID reuse.
type ProcessKey struct {
	CgroupID    uint64 `json:"cgroup_id"`
	TGID        uint32 `json:"tgid"`
	StartTimeNS uint64 `json:"start_time_ns"`
}

func (k ProcessKey) String() string {
	return fmt.Sprintf("cg:%d/tgid:%d/start:%d", k.CgroupID, k.TGID, k.StartTimeNS)
}

// RawExecEvent matches the memory layout of struct exec_event in bpf/execve_events.c
// Total size: 8 + 8 + 8 + 8 + 8 + 4 + 4 + 4 + 4 + 4 + 4 + 16 + 256 = 336 bytes.
const RawExecEventSize = 336

type RawExecEvent struct {
	TimestampNS       uint64
	CgroupID          uint64
	SeqNum            uint64
	StartTimeNS       uint64
	ParentStartTimeNS uint64

	TID        uint32
	TGID       uint32
	ParentTGID uint32
	UID        uint32
	GID        uint32
	Pad        uint32

	Comm     [16]byte
	Filename [256]byte
}

// SecurityEvent is the enriched userspace event structure.
type SecurityEvent struct {
	Raw               RawExecEvent     `json:"raw"`
	Key               ProcessKey       `json:"key"`
	ParentKey         ProcessKey       `json:"parent_key"`
	CapturedAt        time.Time        `json:"captured_at"`
	KernelTimeNS      uint64           `json:"kernel_time_ns"`
	SeqNum            uint64           `json:"seq_num"`
	CgroupID          uint64           `json:"cgroup_id"`
	TID               uint32           `json:"tid"`
	TGID              uint32           `json:"tgid"`
	ParentTGID        uint32           `json:"parent_tgid"`
	StartTimeNS       uint64           `json:"start_time_ns"`
	ParentStartTimeNS uint64           `json:"parent_start_time_ns"`
	UID               uint32           `json:"uid"`
	GID               uint32           `json:"gid"`
	Comm              string           `json:"comm"`
	Filename          string           `json:"filename"`
	State             AttributionState `json:"attribution_state"`
	ContainerID       string           `json:"container_id,omitempty"`
	ContainerName     string           `json:"container_name,omitempty"`
	Image             string           `json:"image,omitempty"`
	CgroupPath        string           `json:"cgroup_path,omitempty"`
	PendingRetries    int              `json:"pending_retries,omitempty"`
}

// DecodeRawExecEvent decodes bytes into RawExecEvent without reflection.
func DecodeRawExecEvent(buf []byte, target *RawExecEvent) error {
	if len(buf) < RawExecEventSize {
		return fmt.Errorf("buffer too short: expected %d bytes, got %d", RawExecEventSize, len(buf))
	}

	target.TimestampNS = binary.LittleEndian.Uint64(buf[0:8])
	target.CgroupID = binary.LittleEndian.Uint64(buf[8:16])
	target.SeqNum = binary.LittleEndian.Uint64(buf[16:24])
	target.StartTimeNS = binary.LittleEndian.Uint64(buf[24:32])
	target.ParentStartTimeNS = binary.LittleEndian.Uint64(buf[32:40])

	target.TID = binary.LittleEndian.Uint32(buf[40:44])
	target.TGID = binary.LittleEndian.Uint32(buf[44:48])
	target.ParentTGID = binary.LittleEndian.Uint32(buf[48:52])
	target.UID = binary.LittleEndian.Uint32(buf[52:56])
	target.GID = binary.LittleEndian.Uint32(buf[56:60])
	target.Pad = binary.LittleEndian.Uint32(buf[60:64])

	copy(target.Comm[:], buf[64:80])
	copy(target.Filename[:], buf[80:336])

	return nil
}

// NullTerminatedString safely parses a null-terminated byte slice into a string.
func NullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// NewSecurityEvent initializes an enriched event from decoded raw kernel event.
func NewSecurityEvent(raw RawExecEvent) *SecurityEvent {
	comm := NullTerminatedString(raw.Comm[:])
	filename := NullTerminatedString(raw.Filename[:])

	// Fall back to event timestamp if kernel task start_time is 0
	startTime := raw.StartTimeNS
	if startTime == 0 {
		startTime = raw.TimestampNS
	}

	key := ProcessKey{
		CgroupID:    raw.CgroupID,
		TGID:        raw.TGID,
		StartTimeNS: startTime,
	}

	parentKey := ProcessKey{
		CgroupID:    raw.CgroupID, // Default parent cgroup; refined by lineage tracker if cross-cgroup
		TGID:        raw.ParentTGID,
		StartTimeNS: raw.ParentStartTimeNS,
	}

	return &SecurityEvent{
		Raw:               raw,
		Key:               key,
		ParentKey:         parentKey,
		CapturedAt:        time.Now().UTC(),
		KernelTimeNS:      raw.TimestampNS,
		SeqNum:            raw.SeqNum,
		CgroupID:          raw.CgroupID,
		TID:               raw.TID,
		TGID:              raw.TGID,
		ParentTGID:        raw.ParentTGID,
		StartTimeNS:       startTime,
		ParentStartTimeNS: raw.ParentStartTimeNS,
		UID:               raw.UID,
		GID:               raw.GID,
		Comm:              comm,
		Filename:          filename,
		State:             AttributionPending,
	}
}

// String returns a structured log line.
func (e *SecurityEvent) String() string {
	name := e.ContainerName
	if name == "" {
		name = "-"
	}
	cid := e.ContainerID
	if cid == "" {
		cid = "-"
	} else if len(cid) > 12 {
		cid = cid[:12]
	}

	return fmt.Sprintf(
		"TIME=%s | STATE=%s | SEQ=%d | CONTAINER=%s | CID=%s | CGROUP=%d | TGID=%d | PPID=%d | START=%d | COMM=%s | EXEC=%s",
		e.CapturedAt.Format(time.RFC3339Nano),
		e.State,
		e.SeqNum,
		name,
		cid,
		e.CgroupID,
		e.TGID,
		e.ParentTGID,
		e.StartTimeNS,
		strings.ReplaceAll(e.Comm, "|", "_"),
		strings.ReplaceAll(e.Filename, "|", "_"),
	)
}

// SequenceTracker tracks monotonic sequence numbers, distinguishing out-of-order arrivals from drops.
type SequenceTracker struct {
	mu           sync.Mutex
	maxSeq       uint64
	initialized  bool
	seen         map[uint64]bool
	windowSize   uint64
	reordered    uint64
	confirmedGap uint64
}

// NewSequenceTracker initializes sequence tracker with a sliding reorder window.
func NewSequenceTracker(windowSize uint64) *SequenceTracker {
	if windowSize == 0 {
		windowSize = 256
	}
	return &SequenceTracker{
		seen:       make(map[uint64]bool),
		windowSize: windowSize,
	}
}

// Observe records a sequence number and returns (isReordered, confirmedGaps).
func (st *SequenceTracker) Observe(seq uint64) (bool, uint64) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if !st.initialized {
		st.initialized = true
		st.maxSeq = seq
		st.seen[seq] = true
		return false, 0
	}

	// 1. Check if it arrived out of order (behind maxSeq)
	if seq < st.maxSeq {
		if !st.seen[seq] {
			st.seen[seq] = true
			st.reordered++
			return true, 0
		}
		// Duplicate sequence
		return false, 0
	}

	// 2. Advance maxSeq
	gap := uint64(0)
	if seq > st.maxSeq+1 {
		gap = seq - (st.maxSeq + 1)
	}

	st.seen[seq] = true
	st.maxSeq = seq

	// 3. Prune seen window
	if st.maxSeq > st.windowSize {
		threshold := st.maxSeq - st.windowSize
		for s := range st.seen {
			if s < threshold {
				delete(st.seen, s)
			}
		}
	}

	return false, gap
}

// TelemetryAccounting tracks fine-grained kernel and userspace pipeline metrics.
type TelemetryAccounting struct {
	// Userspace metrics
	RecordsReceived       atomic.Uint64
	RecordsDecoded        atomic.Uint64
	DecodeFailures        atomic.Uint64
	AttributionPending    atomic.Uint64
	AttributionResolved   atomic.Uint64
	AttributionUnresolved atomic.Uint64
	AttributionStale      atomic.Uint64
	AttributionHost       atomic.Uint64
	QueueOverflows        atomic.Uint64
	SequenceGapsDetected  atomic.Uint64
	ReorderedEvents       atomic.Uint64
	EventsProcessed       atomic.Uint64
	ProcessingFailures    atomic.Uint64

	// Kernel-side metrics read from BPF maps
	KernelHookInvocations  atomic.Uint64
	KernelRingBufferDrops  atomic.Uint64
	KernelRingBufferSubmit atomic.Uint64
	KernelCgroupMapFails   atomic.Uint64
}

// MetricsSnapshot represents an immutable point-in-time metrics report.
type MetricsSnapshot struct {
	Timestamp              time.Time `json:"timestamp"`
	KernelHookInvocations  uint64    `json:"kernel_hook_invocations"`
	KernelRingBufferDrops  uint64    `json:"kernel_ringbuf_reserve_drops"`
	KernelRingBufferSubmit uint64    `json:"kernel_ringbuf_submitted"`
	KernelCgroupMapFails   uint64    `json:"kernel_cgroup_map_fails"`
	RecordsReceived        uint64    `json:"userspace_records_received"`
	RecordsDecoded         uint64    `json:"userspace_records_decoded"`
	DecodeFailures         uint64    `json:"userspace_decode_failures"`
	AttributionPending     uint64    `json:"attribution_pending"`
	AttributionResolved    uint64    `json:"attribution_resolved"`
	AttributionUnresolved  uint64    `json:"attribution_unresolved"`
	AttributionStale       uint64    `json:"attribution_stale_mapping"`
	AttributionHost        uint64    `json:"attribution_host_confirmed"`
	QueueOverflows         uint64    `json:"userspace_queue_overflows"`
	SequenceGapsDetected   uint64    `json:"sequence_gaps_detected"`
	ReorderedEvents        uint64    `json:"reordered_events"`
	EventsProcessed        uint64    `json:"events_processed"`
	ProcessingFailures     uint64    `json:"processing_failures"`
	KernelDropRatePercent  float64   `json:"kernel_drop_rate_pct"`
	UserspaceLossCount     uint64    `json:"userspace_loss_count"`
}

// Snapshot captures the current atomic values.
func (t *TelemetryAccounting) Snapshot() MetricsSnapshot {
	hookCalls := t.KernelHookInvocations.Load()
	rbDrops := t.KernelRingBufferDrops.Load()
	rbSubmit := t.KernelRingBufferSubmit.Load()

	var dropRate float64
	if hookCalls > 0 {
		dropRate = float64(rbDrops) / float64(hookCalls) * 100.0
	}

	received := t.RecordsReceived.Load()
	var lossCount uint64
	if rbSubmit > received {
		lossCount = rbSubmit - received
	}

	return MetricsSnapshot{
		Timestamp:              time.Now().UTC(),
		KernelHookInvocations:  hookCalls,
		KernelRingBufferDrops:  rbDrops,
		KernelRingBufferSubmit: rbSubmit,
		KernelCgroupMapFails:   t.KernelCgroupMapFails.Load(),
		RecordsReceived:        received,
		RecordsDecoded:         t.RecordsDecoded.Load(),
		DecodeFailures:         t.DecodeFailures.Load(),
		AttributionPending:     t.AttributionPending.Load(),
		AttributionResolved:    t.AttributionResolved.Load(),
		AttributionUnresolved:  t.AttributionUnresolved.Load(),
		AttributionStale:       t.AttributionStale.Load(),
		AttributionHost:        t.AttributionHost.Load(),
		QueueOverflows:         t.QueueOverflows.Load(),
		SequenceGapsDetected:   t.SequenceGapsDetected.Load(),
		ReorderedEvents:        t.ReorderedEvents.Load(),
		EventsProcessed:        t.EventsProcessed.Load(),
		ProcessingFailures:     t.ProcessingFailures.Load(),
		KernelDropRatePercent:  dropRate,
		UserspaceLossCount:     lossCount,
	}
}
