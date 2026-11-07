package pipeline

import (
	"context"
	"fmt"
	"sync/atomic"

	"cg-smoke-test/internal/telemetry"
)

// Ingester decodes raw kernel ring buffer records, tracks sequence continuity,
// and submits enriched events into the attribution buffer.
type Ingester struct {
	buffer     *AttributionBuffer
	accounting *telemetry.TelemetryAccounting

	lastSeqNum atomic.Uint64
	hasSeenSeq atomic.Bool
}

// NewIngester constructs an ingester.
func NewIngester(buffer *AttributionBuffer, accounting *telemetry.TelemetryAccounting) *Ingester {
	return &Ingester{
		buffer:     buffer,
		accounting: accounting,
	}
}

// ProcessRawSample unpacks a raw sample from the BPF ring buffer.
func (in *Ingester) ProcessRawSample(ctx context.Context, sample []byte) (*telemetry.SecurityEvent, error) {
	in.accounting.RecordsReceived.Add(1)

	var raw telemetry.RawExecEvent
	if err := telemetry.DecodeRawExecEvent(sample, &raw); err != nil {
		in.accounting.DecodeFailures.Add(1)
		return nil, fmt.Errorf("decoding raw exec event: %w", err)
	}

	in.accounting.RecordsDecoded.Add(1)

	// Check monotonic sequence number continuity
	if in.hasSeenSeq.Load() {
		last := in.lastSeqNum.Load()
		if raw.SeqNum > last+1 {
			gap := raw.SeqNum - (last + 1)
			in.accounting.SequenceGapsDetected.Add(gap)
		}
	} else {
		in.hasSeenSeq.Store(true)
	}
	in.lastSeqNum.Store(raw.SeqNum)

	event := telemetry.NewSecurityEvent(raw)
	in.buffer.Ingest(event)

	return event, nil
}
