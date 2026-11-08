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

// Event flags from kernel eBPF probe.
const (
	FlagStartTimeEstimated       uint32 = 1 << 0
	FlagParentStartTimeEstimated uint32 = 1 << 1
	FlagPathTruncated            uint32 = 1 << 2
	FlagCommTruncated            uint32 = 1 << 3
	FlagExecveat                 uint32 = 1 << 4
	FlagAtEmptyPath              uint32 = 1 << 5
	FlagCommittedExec            uint32 = 1 << 6
	FlagExecFailed               uint32 = 1 << 7
	FlagCgroupMigrated           uint32 = 1 << 8
	FlagSetuidExec               uint32 = 1 << 9
)

// ProcessInstanceKey represents the immutable kernel process identity (TGID + start time).
// This tuple is collision-resistant across PID recycling and invariant under cgroup migration.
type ProcessInstanceKey struct {
	TGID        uint32 `json:"tgid"`
	StartTimeNS uint64 `json:"start_time_ns"`
}

func (k ProcessInstanceKey) String() string {
	return fmt.Sprintf("tgid:%d/start:%d", k.TGID, k.StartTimeNS)
}

// ProcessKey is a structured process identity combining immutable identity with execution context.
type ProcessKey struct {
	CgroupID    uint64 `json:"cgroup_id"`
	TGID        uint32 `json:"tgid"`
	StartTimeNS uint64 `json:"start_time_ns"`
}

func (k ProcessKey) String() string {
	return fmt.Sprintf("cg:%d/tgid:%d/start:%d", k.CgroupID, k.TGID, k.StartTimeNS)
}

// InstanceKey extracts the immutable instance identity tuple.
func (k ProcessKey) InstanceKey() ProcessInstanceKey {
	return ProcessInstanceKey{
		TGID:        k.TGID,
		StartTimeNS: k.StartTimeNS,
	}
}

// RawExecEvent matches the memory layout of struct exec_event in bpf/execve_events.c
// Total size: 6*8 + 6*4 + 4 + 4 + 4 + 4 + 16 + 256 = 360 bytes.
const RawExecEventSize = 360

type RawExecEvent struct {
	TimestampNS       uint64
	CgroupID          uint64
	ParentCgroupID    uint64
	SeqNum            uint64
	StartTimeNS       uint64
	ParentStartTimeNS uint64

	TID        uint32
	TGID       uint32
	ParentTGID uint32
	UID        uint32
	GID        uint32
	Flags      uint32

	Dfd      int32
	AtFlags  uint32
	ExitCode int32
	EUID     uint32

	Comm     [16]byte
	Filename [256]byte
}

// SecurityEvent is the enriched userspace event structure.
type SecurityEvent struct {
	Raw                      RawExecEvent     `json:"raw"`
	Key                      ProcessKey       `json:"key"`
	ParentKey                ProcessKey       `json:"parent_key"`
	CapturedAt               time.Time        `json:"captured_at"`
	KernelTimeNS             uint64           `json:"kernel_time_ns"`
	SeqNum                   uint64           `json:"seq_num"`
	CgroupID                 uint64           `json:"cgroup_id"`
	ParentCgroupID           uint64           `json:"parent_cgroup_id"`
	TID                      uint32           `json:"tid"`
	TGID                     uint32           `json:"tgid"`
	ParentTGID               uint32           `json:"parent_tgid"`
	StartTimeNS              uint64           `json:"start_time_ns"`
	ParentStartTimeNS        uint64           `json:"parent_start_time_ns"`
	StartTimeEstimated       bool             `json:"start_time_estimated"`
	ParentStartTimeEstimated bool             `json:"parent_start_time_estimated"`
	PathTruncated            bool             `json:"path_truncated"`
	CommTruncated            bool             `json:"comm_truncated"`
	Execveat                 bool             `json:"execveat"`
	AtEmptyPath              bool             `json:"at_empty_path"`
	Committed                bool             `json:"committed"`
	Failed                   bool             `json:"failed"`
	CgroupMigrated           bool             `json:"cgroup_migrated"`
	SetuidExec               bool             `json:"setuid_exec"`
	Dfd                      int32            `json:"dfd"`
	AtFlags                  uint32           `json:"at_flags"`
	ExitCode                 int32            `json:"exit_code"`
	UID                      uint32           `json:"uid"`
	EUID                     uint32           `json:"euid"`
	GID                      uint32           `json:"gid"`
	Comm                     string           `json:"comm"`
	Filename                 string           `json:"filename"`
	State                    AttributionState `json:"attribution_state"`
	ContainerID              string           `json:"container_id,omitempty"`
	ContainerName            string           `json:"container_name,omitempty"`
	Image                    string           `json:"image,omitempty"`
	CgroupPath               string           `json:"cgroup_path,omitempty"`
	PendingRetries           int              `json:"pending_retries,omitempty"`
}

// DecodeRawExecEvent decodes bytes into RawExecEvent without reflection.
func DecodeRawExecEvent(buf []byte, target *RawExecEvent) error {
	if len(buf) < RawExecEventSize {
		return fmt.Errorf("buffer too short: expected %d bytes, got %d", RawExecEventSize, len(buf))
	}

	target.TimestampNS = binary.LittleEndian.Uint64(buf[0:8])
	target.CgroupID = binary.LittleEndian.Uint64(buf[8:16])
	target.ParentCgroupID = binary.LittleEndian.Uint64(buf[16:24])
	target.SeqNum = binary.LittleEndian.Uint64(buf[24:32])
	target.StartTimeNS = binary.LittleEndian.Uint64(buf[32:40])
	target.ParentStartTimeNS = binary.LittleEndian.Uint64(buf[40:48])

	target.TID = binary.LittleEndian.Uint32(buf[48:52])
	target.TGID = binary.LittleEndian.Uint32(buf[52:56])
	target.ParentTGID = binary.LittleEndian.Uint32(buf[56:60])
	target.UID = binary.LittleEndian.Uint32(buf[60:64])
	target.GID = binary.LittleEndian.Uint32(buf[64:68])
	target.Flags = binary.LittleEndian.Uint32(buf[68:72])

	target.Dfd = int32(binary.LittleEndian.Uint32(buf[72:76]))
	target.AtFlags = binary.LittleEndian.Uint32(buf[76:80])
	target.ExitCode = int32(binary.LittleEndian.Uint32(buf[80:84]))
	target.EUID = binary.LittleEndian.Uint32(buf[84:88])

	copy(target.Comm[:], buf[88:104])
	copy(target.Filename[:], buf[104:360])

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

	startTimeEstimated := (raw.Flags & FlagStartTimeEstimated) != 0
	parentStartTimeEstimated := (raw.Flags & FlagParentStartTimeEstimated) != 0
	pathTruncated := (raw.Flags & FlagPathTruncated) != 0
	commTruncated := (raw.Flags & FlagCommTruncated) != 0
	execveat := (raw.Flags & FlagExecveat) != 0
	atEmptyPath := (raw.Flags & FlagAtEmptyPath) != 0
	committed := (raw.Flags & FlagCommittedExec) != 0
	failed := (raw.Flags & FlagExecFailed) != 0
	cgroupMigrated := (raw.Flags & FlagCgroupMigrated) != 0
	setuidExec := (raw.Flags & FlagSetuidExec) != 0

	key := ProcessKey{
		CgroupID:    raw.CgroupID,
		TGID:        raw.TGID,
		StartTimeNS: raw.StartTimeNS,
	}

	parentCgroupID := raw.ParentCgroupID
	if parentCgroupID == 0 {
		parentCgroupID = raw.CgroupID
	}

	parentKey := ProcessKey{
		CgroupID:    parentCgroupID,
		TGID:        raw.ParentTGID,
		StartTimeNS: raw.ParentStartTimeNS,
	}

	return &SecurityEvent{
		Raw:                      raw,
		Key:                      key,
		ParentKey:                parentKey,
		CapturedAt:               time.Now().UTC(),
		KernelTimeNS:             raw.TimestampNS,
		SeqNum:                   raw.SeqNum,
		CgroupID:                 raw.CgroupID,
		ParentCgroupID:           parentCgroupID,
		TID:                      raw.TID,
		TGID:                     raw.TGID,
		ParentTGID:               raw.ParentTGID,
		StartTimeNS:              raw.StartTimeNS,
		ParentStartTimeNS:        raw.ParentStartTimeNS,
		StartTimeEstimated:       startTimeEstimated,
		ParentStartTimeEstimated: parentStartTimeEstimated,
		PathTruncated:            pathTruncated,
		CommTruncated:            commTruncated,
		Execveat:                 execveat,
		AtEmptyPath:              atEmptyPath,
		Committed:                committed,
		Failed:                   failed,
		CgroupMigrated:           cgroupMigrated,
		SetuidExec:               setuidExec,
		Dfd:                      raw.Dfd,
		AtFlags:                  raw.AtFlags,
		ExitCode:                 raw.ExitCode,
		UID:                      raw.UID,
		EUID:                     raw.EUID,
		GID:                      raw.GID,
		Comm:                     comm,
		Filename:                 filename,
		State:                    AttributionPending,
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

	estTag := ""
	if e.StartTimeEstimated {
		estTag = "(est)"
	}

	statusTag := "EXEC"
	if e.Failed {
		statusTag = fmt.Sprintf("FAIL(%d)", e.ExitCode)
	} else if e.Committed {
		statusTag = "COMMITTED"
	}

	return fmt.Sprintf(
		"TIME=%s | STATUS=%s | STATE=%s | SEQ=%d | CONTAINER=%s | CID=%s | CGROUP=%d (PCG=%d) | TGID=%d | TID=%d | PPID=%d | START=%d%s | COMM=%s | EXEC=%s",
		e.CapturedAt.Format(time.RFC3339Nano),
		statusTag,
		e.State,
		e.SeqNum,
		name,
		cid,
		e.CgroupID,
		e.ParentCgroupID,
		e.TGID,
		e.TID,
		e.ParentTGID,
		e.StartTimeNS,
		estTag,
		strings.ReplaceAll(e.Comm, "|", "_"),
		strings.ReplaceAll(e.Filename, "|", "_"),
	)
}

// SequenceTracker tracks monotonic sequence numbers using a sliding watermark window,
// accurately separating transient multi-core commit reordering from genuine permanent event loss.
type SequenceTracker struct {
	mu             sync.Mutex
	maxSeq         uint64
	initialized    bool
	pendingGaps    map[uint64]time.Time
	reorderedCount uint64
	confirmedLoss  uint64
	windowSize     uint64
	retireTimeout  time.Duration
}

// NewSequenceTracker initializes sequence tracker with a sliding reorder window.
func NewSequenceTracker(windowSize uint64) *SequenceTracker {
	if windowSize == 0 {
		windowSize = 1024
	}
	return &SequenceTracker{
		pendingGaps:   make(map[uint64]time.Time),
		windowSize:    windowSize,
		retireTimeout: 2 * time.Second,
	}
}

// Observe records a sequence number and returns (isReordered, newlyConfirmedLosses).
func (st *SequenceTracker) Observe(seq uint64) (bool, uint64) {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()

	if !st.initialized {
		st.initialized = true
		st.maxSeq = seq
		return false, 0
	}

	// Case 1: Out-of-order delivery behind maxSeq
	if seq <= st.maxSeq {
		if _, isPending := st.pendingGaps[seq]; isPending {
			delete(st.pendingGaps, seq)
			st.reorderedCount++
			return true, 0
		}
		// Duplicate or already retired sequence number
		return false, 0
	}

	// Case 2: Sequence jump ahead (new potential gaps created)
	if seq > st.maxSeq+1 {
		for missing := st.maxSeq + 1; missing < seq; missing++ {
			st.pendingGaps[missing] = now
		}
	}
	st.maxSeq = seq

	// Case 3: Retire pending gaps that have fallen behind the watermark window
	newlyConfirmed := uint64(0)
	if st.maxSeq > st.windowSize {
		watermark := st.maxSeq - st.windowSize
		for missing, created := range st.pendingGaps {
			if missing <= watermark || now.Sub(created) > st.retireTimeout {
				delete(st.pendingGaps, missing)
				st.confirmedLoss++
				newlyConfirmed++
			}
		}
	}

	return false, newlyConfirmed
}

// FlushRetires forces retirement of all remaining pending gaps on shutdown.
func (st *SequenceTracker) FlushRetires() uint64 {
	st.mu.Lock()
	defer st.mu.Unlock()

	flushed := uint64(len(st.pendingGaps))
	st.confirmedLoss += flushed
	st.pendingGaps = make(map[uint64]time.Time)
	return flushed
}

// Stats returns a snapshot of sequence metrics.
func (st *SequenceTracker) Stats() (reordered, confirmedLoss, pendingCount uint64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.reorderedCount, st.confirmedLoss, uint64(len(st.pendingGaps))
}

// TelemetryAccounting tracks fine-grained kernel and userspace pipeline metrics.
type TelemetryAccounting struct {
	// Userspace metrics
	RecordsReceived               atomic.Uint64
	RecordsDecoded                atomic.Uint64
	DecodeFailures                atomic.Uint64
	AttributionPendingTransitions atomic.Uint64 // Cumulative transitions into PENDING
	CurrentPendingQueueDepth      atomic.Uint64 // Live gauge: current buffered events
	PeakPendingQueueDepth         atomic.Uint64 // Gauge: maximum observed pending queue size
	AttributionResolved           atomic.Uint64 // Cumulative events resolved to container
	AttributionUnresolved         atomic.Uint64 // Cumulative events remaining unmapped/expired
	AttributionStale              atomic.Uint64 // Cumulative events resolved via tombstone
	AttributionHost               atomic.Uint64 // Cumulative host-confirmed events
	QueueOverflows                atomic.Uint64
	SequenceGapsDetected          atomic.Uint64
	ReorderedEvents               atomic.Uint64
	EventsProcessed               atomic.Uint64
	ProcessingFailures            atomic.Uint64

	// Kernel-side metrics read from BPF maps
	KernelHookInvocations  atomic.Uint64
	KernelRingBufferDrops  atomic.Uint64
	KernelRingBufferSubmit atomic.Uint64
	KernelCgroupMapFails   atomic.Uint64
}

// MetricsSnapshot represents an immutable point-in-time metrics report.
type MetricsSnapshot struct {
	Timestamp                     time.Time `json:"timestamp"`
	KernelHookInvocations         uint64    `json:"kernel_hook_invocations"`
	KernelRingBufferDrops         uint64    `json:"kernel_ringbuf_reserve_drops"`
	KernelRingBufferSubmit        uint64    `json:"kernel_ringbuf_submitted"`
	KernelCgroupMapFails          uint64    `json:"kernel_cgroup_map_fails"`
	RecordsReceived               uint64    `json:"userspace_records_received"`
	RecordsDecoded                uint64    `json:"userspace_records_decoded"`
	DecodeFailures                uint64    `json:"userspace_decode_failures"`
	AttributionPendingTransitions uint64    `json:"attribution_pending_transitions"`
	CurrentPendingQueueDepth      uint64    `json:"current_pending_queue_depth"`
	PeakPendingQueueDepth         uint64    `json:"peak_pending_queue_depth"`
	AttributionResolved           uint64    `json:"attribution_resolved"`
	AttributionUnresolved         uint64    `json:"attribution_unresolved"`
	AttributionStale              uint64    `json:"attribution_stale_mapping"`
	AttributionHost               uint64    `json:"attribution_host_confirmed"`
	QueueOverflows                uint64    `json:"userspace_queue_overflows"`
	SequenceGapsDetected          uint64    `json:"sequence_gaps_detected"`
	ReorderedEvents               uint64    `json:"reordered_events"`
	EventsProcessed               uint64    `json:"events_processed"`
	ProcessingFailures            uint64    `json:"processing_failures"`
	KernelDropRatePercent         float64   `json:"kernel_drop_rate_pct"`
	UserspaceLossCount            uint64    `json:"userspace_loss_count"`
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
		Timestamp:                     time.Now().UTC(),
		KernelHookInvocations:         hookCalls,
		KernelRingBufferDrops:         rbDrops,
		KernelRingBufferSubmit:        rbSubmit,
		KernelCgroupMapFails:          t.KernelCgroupMapFails.Load(),
		RecordsReceived:               received,
		RecordsDecoded:                t.RecordsDecoded.Load(),
		DecodeFailures:                t.DecodeFailures.Load(),
		AttributionPendingTransitions: t.AttributionPendingTransitions.Load(),
		CurrentPendingQueueDepth:      t.CurrentPendingQueueDepth.Load(),
		PeakPendingQueueDepth:         t.PeakPendingQueueDepth.Load(),
		AttributionResolved:           t.AttributionResolved.Load(),
		AttributionUnresolved:         t.AttributionUnresolved.Load(),
		AttributionStale:              t.AttributionStale.Load(),
		AttributionHost:               t.AttributionHost.Load(),
		QueueOverflows:                t.QueueOverflows.Load(),
		SequenceGapsDetected:          t.SequenceGapsDetected.Load(),
		ReorderedEvents:               t.ReorderedEvents.Load(),
		EventsProcessed:               t.EventsProcessed.Load(),
		ProcessingFailures:            t.ProcessingFailures.Load(),
		KernelDropRatePercent:         dropRate,
		UserspaceLossCount:            lossCount,
	}
}
