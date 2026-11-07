package lineage

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"cg-smoke-test/internal/telemetry"
)

// ProcessNode represents a single process node in the execution graph.
type ProcessNode struct {
	CompositeKey uint64    `json:"composite_key"`
	TGID         uint32    `json:"tgid"`
	TID          uint32    `json:"tid"`
	PPID         uint32    `json:"ppid"`
	UID          uint32    `json:"uid"`
	GID          uint32    `json:"gid"`
	CgroupID     uint64    `json:"cgroup_id"`
	ContainerID  string    `json:"container_id"`
	Comm         string    `json:"comm"`
	Executable   string    `json:"executable"`
	StartTime    time.Time `json:"start_time"`
	ParentKey    uint64    `json:"parent_key,omitempty"`
}

// LineageTracker maintains a bounded, container-aware process relationship store.
type LineageTracker struct {
	mu        sync.RWMutex
	processes map[uint64]*ProcessNode // key: composite (cgroupID ^ tgid)
	maxNodes  int
	ttl       time.Duration
}

// NewLineageTracker initializes the lineage store.
func NewLineageTracker(maxNodes int, ttl time.Duration) *LineageTracker {
	if maxNodes <= 0 {
		maxNodes = 20000
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &LineageTracker{
		processes: make(map[uint64]*ProcessNode),
		maxNodes:  maxNodes,
		ttl:       ttl,
	}
}

// compositeKey forms a collision-resistant key combining cgroup and TGID to handle PID reuse.
func compositeKey(cgroupID uint64, tgid uint32) uint64 {
	return (cgroupID << 32) ^ uint64(tgid)
}

// RecordExec records an execve event into the lineage store.
func (lt *LineageTracker) RecordExec(event *telemetry.SecurityEvent) *ProcessNode {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	// Evict stale nodes if capacity is reached
	if len(lt.processes) >= lt.maxNodes {
		lt.evictOldest()
	}

	key := compositeKey(event.CgroupID, event.TGID)
	node := &ProcessNode{
		CompositeKey: key,
		TGID:         event.TGID,
		TID:          event.TID,
		UID:          event.UID,
		GID:          event.GID,
		CgroupID:     event.CgroupID,
		ContainerID:  event.ContainerID,
		Comm:         event.Comm,
		Executable:   event.Filename,
		StartTime:    event.CapturedAt,
	}

	lt.processes[key] = node
	return node
}

// GetProcess retrieves a process node by cgroup and TGID.
func (lt *LineageTracker) GetProcess(cgroupID uint64, tgid uint32) (*ProcessNode, bool) {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	node, exists := lt.processes[compositeKey(cgroupID, tgid)]
	return node, exists
}

// FormatChain returns a human-readable lineage string for detection and forensics.
func (lt *LineageTracker) FormatChain(node *ProcessNode) string {
	if node == nil {
		return "unknown"
	}

	chain := []string{fmt.Sprintf("%s(tgid:%d)", node.Executable, node.TGID)}
	current := node

	// Walk parent links where available
	visited := make(map[uint64]bool)
	visited[node.CompositeKey] = true

	for current.ParentKey != 0 {
		if visited[current.ParentKey] {
			break
		}
		visited[current.ParentKey] = true

		lt.mu.RLock()
		parent, ok := lt.processes[current.ParentKey]
		lt.mu.RUnlock()

		if !ok {
			break
		}
		chain = append([]string{fmt.Sprintf("%s(tgid:%d)", parent.Executable, parent.TGID)}, chain...)
		current = parent
	}

	return strings.Join(chain, " -> ")
}

func (lt *LineageTracker) evictOldest() {
	var oldestKey uint64
	var oldestTime time.Time
	first := true

	for k, v := range lt.processes {
		if first || v.StartTime.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.StartTime
			first = false
		}
	}

	if !first {
		delete(lt.processes, oldestKey)
	}
}

// PruneExpired removes processes older than TTL.
func (lt *LineageTracker) PruneExpired(now time.Time) int {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	pruned := 0
	for k, v := range lt.processes {
		if now.Sub(v.StartTime) > lt.ttl {
			delete(lt.processes, k)
			pruned++
		}
	}
	return pruned
}
