package collector

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"cg-smoke-test/internal/pipeline"
	"cg-smoke-test/internal/telemetry"
)

// Metric indexes corresponding to bpf/execve_events.c
const (
	MetricHookCalls      = 0
	MetricReserveDrops   = 1
	MetricSubmitted      = 2
	MetricCgroupMapFails = 3
	MetricMaxIndex       = 4
)

// CollectorConfig configures ring buffer parameters and benchmark modes.
type CollectorConfig struct {
	RingBufSizeKB     int // Ring buffer size in KB (must be power-of-two * page size, e.g. 64, 256, 1024, 16384)
	SimulatedPauseSec int // Artificially delay initial ring buffer reader startup by N seconds
	SimulatedDelayMS  int // Artificially delay each sample read by N milliseconds
}

// DefaultCollectorConfig returns the production defaults (16MB buffer, no backpressure).
func DefaultCollectorConfig() CollectorConfig {
	return CollectorConfig{
		RingBufSizeKB:     16384, // 16 MB default
		SimulatedPauseSec: 0,
		SimulatedDelayMS:  0,
	}
}

// BPFCollector manages eBPF loading, ring buffer consumption, and kernel metric polling.
type BPFCollector struct {
	bpfPath    string
	cfg        CollectorConfig
	ingester   *pipeline.Ingester
	accounting *telemetry.TelemetryAccounting

	spec       *ebpf.CollectionSpec
	collection *ebpf.Collection
	tpLink     link.Link
	ringReader *ringbuf.Reader

	mu     sync.Mutex
	closed bool
}

// NewBPFCollector initializes the collector configuration with defaults.
func NewBPFCollector(
	bpfPath string,
	ingester *pipeline.Ingester,
	accounting *telemetry.TelemetryAccounting,
) *BPFCollector {
	return NewBPFCollectorWithConfig(bpfPath, DefaultCollectorConfig(), ingester, accounting)
}

// NewBPFCollectorWithConfig initializes the collector with custom ring buffer and benchmark options.
func NewBPFCollectorWithConfig(
	bpfPath string,
	cfg CollectorConfig,
	ingester *pipeline.Ingester,
	accounting *telemetry.TelemetryAccounting,
) *BPFCollector {
	if cfg.RingBufSizeKB <= 0 {
		cfg.RingBufSizeKB = 16384
	}
	return &BPFCollector{
		bpfPath:    bpfPath,
		cfg:        cfg,
		ingester:   ingester,
		accounting: accounting,
	}
}

// Start loads the eBPF object, attaches the tracepoint, and starts ring buffer draining.
func (c *BPFCollector) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(c.bpfPath)
	if err != nil {
		return fmt.Errorf("loading BPF collection spec from %s: %w", c.bpfPath, err)
	}
	c.spec = spec

	if c.cfg.RingBufSizeKB > 0 && spec.Maps["events"] != nil {
		targetBytes := uint32(c.cfg.RingBufSizeKB * 1024)
		spec.Maps["events"].MaxEntries = targetBytes
		log.Printf("[collector] configured Ring Buffer capacity: %d KiB (%d bytes)", c.cfg.RingBufSizeKB, targetBytes)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("creating BPF collection: %w", err)
	}
	c.collection = collection

	prog := collection.Programs["cg_execve_events"]
	if prog == nil {
		collection.Close()
		return fmt.Errorf("BPF program 'cg_execve_events' not found in object")
	}

	eventsMap := collection.Maps["events"]
	if eventsMap == nil {
		collection.Close()
		return fmt.Errorf("ring buffer map 'events' not found")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		collection.Close()
		return fmt.Errorf("attaching tracepoint sys_enter_execve: %w", err)
	}
	c.tpLink = tp

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		tp.Close()
		collection.Close()
		return fmt.Errorf("initializing ring buffer reader: %w", err)
	}
	c.ringReader = reader

	log.Printf("[collector] eBPF program loaded: %s (tracepoint sys_enter_execve attached)", c.bpfPath)

	// Clean shutdown helper: when ctx cancels, close ring reader to unblock reader.Read()
	go func() {
		<-ctx.Done()
		c.Close()
	}()

	// Start background kernel metrics sync loop
	go c.pollKernelMetrics(ctx)

	// Start ring buffer reader loop
	go c.readLoop(ctx)

	return nil
}

func (c *BPFCollector) readLoop(ctx context.Context) {
	defer c.Close()

	if c.cfg.SimulatedPauseSec > 0 {
		log.Printf("[collector] [BENCHMARK] Simulating userspace backpressure: pausing reader for %d seconds...", c.cfg.SimulatedPauseSec)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(c.cfg.SimulatedPauseSec) * time.Second):
			log.Printf("[collector] [BENCHMARK] Userspace backpressure pause complete. Resuming ring buffer consumption.")
		}
	}

	for {
		if c.cfg.SimulatedDelayMS > 0 {
			time.Sleep(time.Duration(c.cfg.SimulatedDelayMS) * time.Millisecond)
		}

		record, err := c.ringReader.Read()
		if err != nil {
			if ctx.Err() != nil || c.isClosed() {
				log.Println("[collector] ring buffer consumer stopped gracefully")
				return
			}
			log.Printf("[collector] ring buffer read error: %v", err)
			continue
		}

		if _, err := c.ingester.ProcessRawSample(ctx, record.RawSample); err != nil {
			log.Printf("[collector] error processing sample: %v", err)
		}
	}
}

func (c *BPFCollector) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Close safely unloads eBPF programs, links, and readers.
func (c *BPFCollector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	var firstErr error
	if c.ringReader != nil {
		if err := c.ringReader.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.tpLink != nil {
		if err := c.tpLink.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.collection != nil {
		c.collection.Close()
	}

	return firstErr
}

// PollKernelMetrics reads hardware/kernel counters directly from BPF maps.
func (c *BPFCollector) PollKernelMetrics() error {
	if c.collection == nil {
		return fmt.Errorf("bpf collection not loaded")
	}

	counterMap := c.collection.Maps["telemetry_counters"]
	if counterMap == nil {
		return fmt.Errorf("telemetry_counters map not found")
	}

	for idx := uint32(0); idx < MetricMaxIndex; idx++ {
		var val uint64
		if err := counterMap.Lookup(&idx, &val); err == nil {
			switch idx {
			case MetricHookCalls:
				c.accounting.KernelHookInvocations.Store(val)
			case MetricReserveDrops:
				c.accounting.KernelRingBufferDrops.Store(val)
			case MetricSubmitted:
				c.accounting.KernelRingBufferSubmit.Store(val)
			case MetricCgroupMapFails:
				c.accounting.KernelCgroupMapFails.Store(val)
			}
		}
	}

	return nil
}

func (c *BPFCollector) pollKernelMetrics(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// One final poll on shutdown
			_ = c.PollKernelMetrics()
			return
		case <-ticker.C:
			_ = c.PollKernelMetrics()
		}
	}
}
