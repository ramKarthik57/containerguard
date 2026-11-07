package pipeline

import (
	"container/list"
	"context"
	"sync"
	"time"

	"cg-smoke-test/internal/container"
	"cg-smoke-test/internal/telemetry"
)

// Config configures pipeline queue limits and retry parameters.
type Config struct {
	MaxPendingCapacity int
	PendingTTL         time.Duration
	ReconcileInterval  time.Duration
	OutputChannelSize  int
}

// DefaultConfig provides conservative research defaults.
func DefaultConfig() Config {
	return Config{
		MaxPendingCapacity: 10000,
		PendingTTL:         2 * time.Second,
		ReconcileInterval:  100 * time.Millisecond,
		OutputChannelSize:  5000,
	}
}

// AttributionBuffer buffers events whose cgroup identity is not yet resolved,
// re-evaluating them when Docker lifecycle events occur or expiring them on timeout.
type AttributionBuffer struct {
	cfg        Config
	resolver   *container.ContainerResolver
	accounting *telemetry.TelemetryAccounting

	mu          sync.Mutex
	pendingList *list.List                 // Chronological list of *telemetry.SecurityEvent
	byCgroup    map[uint64][]*list.Element // cgroup -> list elements for O(1) lookup on container start

	outChan chan *telemetry.SecurityEvent
}

// NewAttributionBuffer creates an attribution buffer.
func NewAttributionBuffer(
	cfg Config,
	resolver *container.ContainerResolver,
	accounting *telemetry.TelemetryAccounting,
) *AttributionBuffer {
	return &AttributionBuffer{
		cfg:         cfg,
		resolver:    resolver,
		accounting:  accounting,
		pendingList: list.New(),
		byCgroup:    make(map[uint64][]*list.Element),
		outChan:     make(chan *telemetry.SecurityEvent, cfg.OutputChannelSize),
	}
}

// Output returns the channel of fully attributed and chronologically reconciled events.
func (ab *AttributionBuffer) Output() <-chan *telemetry.SecurityEvent {
	return ab.outChan
}

// Ingest handles an incoming security event.
func (ab *AttributionBuffer) Ingest(event *telemetry.SecurityEvent) {
	info, state := ab.resolver.Resolve(event.CgroupID)

	switch state {
	case telemetry.AttributionResolved:
		event.State = telemetry.AttributionResolved
		event.ContainerID = info.ID
		event.ContainerName = info.Name
		event.Image = info.Image
		event.CgroupPath = info.CgroupPath
		ab.accounting.AttributionResolved.Add(1)
		ab.emit(event)

	case telemetry.AttributionHostConfirmed:
		event.State = telemetry.AttributionHostConfirmed
		event.ContainerName = "HOST"
		event.ContainerID = "host"
		event.CgroupPath = "/"
		ab.accounting.AttributionHost.Add(1)
		ab.emit(event)

	case telemetry.AttributionStaleMapping:
		event.State = telemetry.AttributionStaleMapping
		event.ContainerID = info.ID
		event.ContainerName = info.Name
		event.Image = info.Image
		event.CgroupPath = info.CgroupPath
		ab.accounting.AttributionStale.Add(1)
		ab.emit(event)

	case telemetry.AttributionPending:
		ab.bufferPending(event)
	}
}

func (ab *AttributionBuffer) bufferPending(event *telemetry.SecurityEvent) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	// Enforce bounded queue capacity
	if ab.pendingList.Len() >= ab.cfg.MaxPendingCapacity {
		// Evict oldest pending event as UNRESOLVED
		oldestElem := ab.pendingList.Front()
		if oldestElem != nil {
			oldest := ab.pendingList.Remove(oldestElem).(*telemetry.SecurityEvent)
			ab.cleanupCgroupIndex(oldest.CgroupID, oldestElem)
			oldest.State = telemetry.AttributionUnresolved
			ab.accounting.QueueOverflows.Add(1)
			ab.accounting.AttributionUnresolved.Add(1)
			ab.emit(oldest)
		}
	}

	event.State = telemetry.AttributionPending
	ab.accounting.AttributionPending.Add(1)

	elem := ab.pendingList.PushBack(event)
	ab.byCgroup[event.CgroupID] = append(ab.byCgroup[event.CgroupID], elem)
}

func (ab *AttributionBuffer) cleanupCgroupIndex(cgroupID uint64, targetElem *list.Element) {
	elements := ab.byCgroup[cgroupID]
	for i, elem := range elements {
		if elem == targetElem {
			ab.byCgroup[cgroupID] = append(elements[:i], elements[i+1:]...)
			break
		}
	}
	if len(ab.byCgroup[cgroupID]) == 0 {
		delete(ab.byCgroup, cgroupID)
	}
}

// ResolveForCgroup immediately resolves all pending events for a newly mapped container.
func (ab *AttributionBuffer) ResolveForCgroup(cgroupID uint64, info container.ContainerInfo) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	elements, found := ab.byCgroup[cgroupID]
	if !found || len(elements) == 0 {
		return
	}

	for _, elem := range elements {
		event := ab.pendingList.Remove(elem).(*telemetry.SecurityEvent)
		event.State = telemetry.AttributionResolved
		event.ContainerID = info.ID
		event.ContainerName = info.Name
		event.Image = info.Image
		event.CgroupPath = info.CgroupPath
		ab.accounting.AttributionResolved.Add(1)
		ab.emit(event)
	}

	delete(ab.byCgroup, cgroupID)
}

// ExpireStale sweeps the pending queue and expires events older than PendingTTL.
func (ab *AttributionBuffer) ExpireStale(now time.Time) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	for elem := ab.pendingList.Front(); elem != nil; {
		next := elem.Next()
		event := elem.Value.(*telemetry.SecurityEvent)

		if now.Sub(event.CapturedAt) > ab.cfg.PendingTTL {
			ab.pendingList.Remove(elem)
			ab.cleanupCgroupIndex(event.CgroupID, elem)

			// One final check before declaring UNRESOLVED
			info, state := ab.resolver.Resolve(event.CgroupID)
			if state == telemetry.AttributionResolved || state == telemetry.AttributionHostConfirmed {
				event.State = state
				event.ContainerID = info.ID
				event.ContainerName = info.Name
				event.Image = info.Image
				event.CgroupPath = info.CgroupPath
				ab.accounting.AttributionResolved.Add(1)
			} else {
				event.State = telemetry.AttributionUnresolved
				ab.accounting.AttributionUnresolved.Add(1)
			}
			ab.emit(event)
		} else {
			// Because pendingList is FIFO ordered by arrival, older items are at the front.
			// Once we encounter an item within TTL, subsequent items are also within TTL.
			break
		}

		elem = next
	}
}

func (ab *AttributionBuffer) emit(event *telemetry.SecurityEvent) {
	select {
	case ab.outChan <- event:
	default:
		ab.accounting.QueueOverflows.Add(1)
	}
}

// Run starts the reconciliation and lifecycle-driven resolution loops.
func (ab *AttributionBuffer) Run(ctx context.Context) {
	ticker := time.NewTicker(ab.cfg.ReconcileInterval)
	defer ticker.Stop()

	updates := ab.resolver.Updates()

	for {
		select {
		case <-ctx.Done():
			// Flush pending events as UNRESOLVED on shutdown
			ab.ExpireStale(time.Now().Add(24 * time.Hour))
			return

		case update, ok := <-updates:
			if !ok {
				updates = nil
				continue
			}
			if update.Action == "start" || update.Action == "restart" || update.Action == "rename" {
				ab.ResolveForCgroup(update.CgroupID, update.Info)
			}

		case now := <-ticker.C:
			ab.ExpireStale(now)
		}
	}
}
