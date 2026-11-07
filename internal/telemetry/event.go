package telemetry

import (
	"encoding/binary"
	"fmt"
	"strings"
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

// RawExecEvent matches the exact memory layout of struct exec_event in bpf/execve_events.c
// Size: 8 + 8 + 8 + 4 + 4 + 4 + 4 + 16 + 256 = 312 bytes.
const RawExecEventSize = 312

type RawExecEvent struct {
	TimestampNS uint64
	CgroupID    uint64
	SeqNum      uint64

	TID  uint32
	TGID uint32
	UID  uint32
	GID  uint32

	Comm     [16]byte
	Filename [256]byte
}

// SecurityEvent is the enriched userspace event structure.
type SecurityEvent struct {
	Raw            RawExecEvent     `json:"raw"`
	CapturedAt     time.Time        `json:"captured_at"`
	KernelTimeNS   uint64           `json:"kernel_time_ns"`
	SeqNum         uint64           `json:"seq_num"`
	CgroupID       uint64           `json:"cgroup_id"`
	TID            uint32           `json:"tid"`
	TGID           uint32           `json:"tgid"`
	UID            uint32           `json:"uid"`
	GID            uint32           `json:"gid"`
	Comm           string           `json:"comm"`
	Filename       string           `json:"filename"`
	State          AttributionState `json:"attribution_state"`
	ContainerID    string           `json:"container_id,omitempty"`
	ContainerName  string           `json:"container_name,omitempty"`
	Image          string           `json:"image,omitempty"`
	CgroupPath     string           `json:"cgroup_path,omitempty"`
	PendingRetries int              `json:"pending_retries,omitempty"`
}

// DecodeRawExecEvent decodes bytes into RawExecEvent without reflection.
func DecodeRawExecEvent(buf []byte, target *RawExecEvent) error {
	if len(buf) < RawExecEventSize {
		return fmt.Errorf("buffer too short: expected %d bytes, got %d", RawExecEventSize, len(buf))
	}

	target.TimestampNS = binary.LittleEndian.Uint64(buf[0:8])
	target.CgroupID = binary.LittleEndian.Uint64(buf[8:16])
	target.SeqNum = binary.LittleEndian.Uint64(buf[16:24])

	target.TID = binary.LittleEndian.Uint32(buf[24:28])
	target.TGID = binary.LittleEndian.Uint32(buf[28:32])
	target.UID = binary.LittleEndian.Uint32(buf[32:36])
	target.GID = binary.LittleEndian.Uint32(buf[36:40])

	copy(target.Comm[:], buf[40:56])
	copy(target.Filename[:], buf[56:312])

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

	return &SecurityEvent{
		Raw:          raw,
		CapturedAt:   time.Now().UTC(),
		KernelTimeNS: raw.TimestampNS,
		SeqNum:       raw.SeqNum,
		CgroupID:     raw.CgroupID,
		TID:          raw.TID,
		TGID:         raw.TGID,
		UID:          raw.UID,
		GID:          raw.GID,
		Comm:         comm,
		Filename:     filename,
		State:        AttributionPending,
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
		"TIME=%s | STATE=%s | SEQ=%d | CONTAINER=%s | CID=%s | CGROUP=%d | TGID=%d | TID=%d | UID=%d | COMM=%s | EXEC=%s",
		e.CapturedAt.Format(time.RFC3339Nano),
		e.State,
		e.SeqNum,
		name,
		cid,
		e.CgroupID,
		e.TGID,
		e.TID,
		e.UID,
		strings.ReplaceAll(e.Comm, "|", "_"),
		strings.ReplaceAll(e.Filename, "|", "_"),
	)
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
	EventsProcessed       atomic.Uint64
	ProcessingFailures    atomic.Uint64

	// Kernel-side metrics read from BPF maps
	KernelHookInvocations  atomic.Uint64
	KernelRingBufferDrops  atomic.Uint64
	KernelRingBufferSubmit atomic.Uint64
}

// MetricsSnapshot represents an immutable point-in-time metrics report.
type MetricsSnapshot struct {
	Timestamp              time.Time `json:"timestamp"`
	KernelHookInvocations  uint64    `json:"kernel_hook_invocations"`
	KernelRingBufferDrops  uint64    `json:"kernel_ringbuf_reserve_drops"`
	KernelRingBufferSubmit uint64    `json:"kernel_ringbuf_submitted"`
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
		EventsProcessed:        t.EventsProcessed.Load(),
		ProcessingFailures:     t.ProcessingFailures.Load(),
		KernelDropRatePercent:  dropRate,
		UserspaceLossCount:     lossCount,
	}
}
