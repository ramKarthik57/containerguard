package pipeline

import (
	"context"
	"fmt"

	"cg-smoke-test/internal/telemetry"
)

// Ingester decodes raw kernel ring buffer records, tracks sequence continuity,
// and submits enriched events into the attribution buffer.
type Ingester struct {
	buffer     *AttributionBuffer
	accounting *telemetry.TelemetryAccounting
	tracker    *telemetry.SequenceTracker
}

// NewIngester constructs an ingester with a sequence tracker.
func NewIngester(buffer *AttributionBuffer, accounting *telemetry.TelemetryAccounting) *Ingester {
	return &Ingester{
		buffer:     buffer,
		accounting: accounting,
		tracker:    telemetry.NewSequenceTracker(1024),
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

	// Check monotonic sequence number continuity and multi-core reordering
	isReordered, gap := in.tracker.Observe(raw.SeqNum)
	if isReordered {
		in.accounting.ReorderedEvents.Add(1)
	} else if gap > 0 {
		in.accounting.SequenceGapsDetected.Add(gap)
	}

	event := telemetry.NewSecurityEvent(raw)
	in.buffer.Ingest(event)

	return event, nil
}
