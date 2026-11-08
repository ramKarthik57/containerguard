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
	Key         telemetry.ProcessKey `json:"key"`
	ParentKey   telemetry.ProcessKey `json:"parent_key"`
	UID         uint32               `json:"uid"`
	GID         uint32               `json:"gid"`
	ContainerID string               `json:"container_id"`
	Comm        string               `json:"comm"`
	Executable  string               `json:"executable"`
	StartTime   time.Time            `json:"start_time"`
}

// LineageTracker maintains a bounded, container-isolated process relationship store.
type LineageTracker struct {
	mu        sync.RWMutex
	processes map[telemetry.ProcessKey]*ProcessNode
	maxNodes  int
	ttl       time.Duration
}

// NewLineageTracker initializes the lineage store.
func NewLineageTracker(maxNodes int, ttl time.Duration) *LineageTracker {
	if maxNodes <= 0 {
		maxNodes = 20000
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &LineageTracker{
		processes: make(map[telemetry.ProcessKey]*ProcessNode),
		maxNodes:  maxNodes,
		ttl:       ttl,
	}
}

// RecordExec records an execve event into the lineage store.
func (lt *LineageTracker) RecordExec(event *telemetry.SecurityEvent) *ProcessNode {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	// Enforce bounded storage capacity
	if len(lt.processes) >= lt.maxNodes {
		lt.evictOldest()
	}

	node := &ProcessNode{
		Key:         event.Key,
		ParentKey:   event.ParentKey,
		UID:         event.UID,
		GID:         event.GID,
		ContainerID: event.ContainerID,
		Comm:        event.Comm,
		Executable:  event.Filename,
		StartTime:   event.CapturedAt,
	}

	lt.processes[event.Key] = node
	return node
}

// GetProcess retrieves a process node by its structured key.
func (lt *LineageTracker) GetProcess(key telemetry.ProcessKey) (*ProcessNode, bool) {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	node, exists := lt.processes[key]
	return node, exists
}

// FindProcessByTGID searches the most recent active process for a given cgroup and TGID.
func (lt *LineageTracker) FindProcessByTGID(cgroupID uint64, tgid uint32) (*ProcessNode, bool) {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	var latest *ProcessNode
	for k, node := range lt.processes {
		if k.CgroupID == cgroupID && k.TGID == tgid {
			if latest == nil || node.Key.StartTimeNS > latest.Key.StartTimeNS {
				latest = node
			}
		}
	}

	return latest, latest != nil
}

// FormatChain reconstructs the ancestry chain walking structured parent keys.
func (lt *LineageTracker) FormatChain(node *ProcessNode) string {
	if node == nil {
		return "unknown"
	}

	chain := []string{fmt.Sprintf("%s(tgid:%d,start:%d)", node.Executable, node.Key.TGID, node.Key.StartTimeNS)}
	current := node

	visited := make(map[telemetry.ProcessKey]bool)
	visited[node.Key] = true

	for current.ParentKey.TGID != 0 {
		if visited[current.ParentKey] {
			break
		}
		visited[current.ParentKey] = true

		lt.mu.RLock()
		parent, ok := lt.processes[current.ParentKey]
		if !ok && current.ParentKey.StartTimeNS == 0 {
			// If parent start time was not captured in kernel, fallback to most recent matching TGID
			parent, ok = lt.findProcessByTGIDLocked(current.ParentKey.CgroupID, current.ParentKey.TGID)
		}
		lt.mu.RUnlock()

		if !ok || parent == nil {
			break
		}

		chain = append([]string{fmt.Sprintf("%s(tgid:%d,start:%d)", parent.Executable, parent.Key.TGID, parent.Key.StartTimeNS)}, chain...)
		current = parent
	}

	return strings.Join(chain, " -> ")
}

func (lt *LineageTracker) findProcessByTGIDLocked(cgroupID uint64, tgid uint32) (*ProcessNode, bool) {
	var latest *ProcessNode
	for k, node := range lt.processes {
		if k.CgroupID == cgroupID && k.TGID == tgid {
			if latest == nil || node.Key.StartTimeNS > latest.Key.StartTimeNS {
				latest = node
			}
		}
	}
	return latest, latest != nil
}

func (lt *LineageTracker) evictOldest() {
	var oldestKey telemetry.ProcessKey
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
