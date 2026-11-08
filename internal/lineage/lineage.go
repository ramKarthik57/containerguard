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
	Key               telemetry.ProcessKey         `json:"key"`
	InstanceKey       telemetry.ProcessInstanceKey `json:"instance_key"`
	ParentKey         telemetry.ProcessKey         `json:"parent_key"`
	ParentInstanceKey telemetry.ProcessInstanceKey `json:"parent_instance_key"`
	UID               uint32                       `json:"uid"`
	GID               uint32                       `json:"gid"`
	ContainerID       string                       `json:"container_id"`
	Comm              string                       `json:"comm"`
	Executable        string                       `json:"executable"`
	StartTime         time.Time                    `json:"start_time"`
	CgroupHistory     []uint64                     `json:"cgroup_history,omitempty"`
}

// LineageTracker maintains a bounded, container-isolated process relationship store.
type LineageTracker struct {
	mu        sync.RWMutex
	instances map[telemetry.ProcessInstanceKey]*ProcessNode
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
		instances: make(map[telemetry.ProcessInstanceKey]*ProcessNode),
		processes: make(map[telemetry.ProcessKey]*ProcessNode),
		maxNodes:  maxNodes,
		ttl:       ttl,
	}
}

// RecordExec records an execve event into the lineage store.
func (lt *LineageTracker) RecordExec(event *telemetry.SecurityEvent) *ProcessNode {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	instKey := event.Key.InstanceKey()
	parentInstKey := event.ParentKey.InstanceKey()

	// Check if this process instance already exists (e.g. earlier exec or migrated cgroup)
	if existing, exists := lt.instances[instKey]; exists {
		if existing.Key.CgroupID != event.CgroupID {
			// Process migrated across cgroup boundaries
			existing.CgroupHistory = append(existing.CgroupHistory, existing.Key.CgroupID)
			event.CgroupMigrated = true
			delete(lt.processes, existing.Key)
			existing.Key = event.Key
			existing.ContainerID = event.ContainerID
			lt.processes[event.Key] = existing
		}
		existing.Comm = event.Comm
		existing.Executable = event.Filename
		existing.UID = event.UID
		existing.GID = event.GID
		return existing
	}

	// Enforce bounded storage capacity
	if len(lt.instances) >= lt.maxNodes {
		lt.evictOldest()
	}

	node := &ProcessNode{
		Key:               event.Key,
		InstanceKey:       instKey,
		ParentKey:         event.ParentKey,
		ParentInstanceKey: parentInstKey,
		UID:               event.UID,
		GID:               event.GID,
		ContainerID:       event.ContainerID,
		Comm:              event.Comm,
		Executable:        event.Filename,
		StartTime:         event.CapturedAt,
	}

	lt.instances[instKey] = node
	lt.processes[event.Key] = node
	return node
}

// GetProcess retrieves a process node by its structured key.
func (lt *LineageTracker) GetProcess(key telemetry.ProcessKey) (*ProcessNode, bool) {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	node, exists := lt.processes[key]
	if !exists {
		node, exists = lt.instances[key.InstanceKey()]
	}
	return node, exists
}

// GetProcessByInstance retrieves a process node by its immutable instance key.
func (lt *LineageTracker) GetProcessByInstance(key telemetry.ProcessInstanceKey) (*ProcessNode, bool) {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	node, exists := lt.instances[key]
	return node, exists
}

// FindProcessByTGID searches the most recent active process for a given cgroup and TGID.
func (lt *LineageTracker) FindProcessByTGID(cgroupID uint64, tgid uint32) (*ProcessNode, bool) {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	var latest *ProcessNode
	for _, node := range lt.instances {
		if (cgroupID == 0 || node.Key.CgroupID == cgroupID) && node.Key.TGID == tgid {
			if latest == nil || node.Key.StartTimeNS > latest.Key.StartTimeNS {
				latest = node
			}
		}
	}

	return latest, latest != nil
}

// FormatChain reconstructs the ancestry chain walking structured parent keys across cgroup boundaries.
func (lt *LineageTracker) FormatChain(node *ProcessNode) string {
	if node == nil {
		return "unknown"
	}

	chain := []string{fmt.Sprintf("%s(tgid:%d,start:%d)", node.Executable, node.Key.TGID, node.Key.StartTimeNS)}
	current := node

	visited := make(map[telemetry.ProcessInstanceKey]bool)
	visited[node.InstanceKey] = true

	for current.ParentKey.TGID != 0 {
		parentInst := current.ParentInstanceKey
		if parentInst.TGID == 0 {
			parentInst = current.ParentKey.InstanceKey()
		}

		if visited[parentInst] {
			break
		}
		visited[parentInst] = true

		lt.mu.RLock()
		parent, ok := lt.instances[parentInst]
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
	for _, node := range lt.instances {
		if (cgroupID == 0 || node.Key.CgroupID == cgroupID) && node.Key.TGID == tgid {
			if latest == nil || node.Key.StartTimeNS > latest.Key.StartTimeNS {
				latest = node
			}
		}
	}
	return latest, latest != nil
}

func (lt *LineageTracker) evictOldest() {
	var oldestInst telemetry.ProcessInstanceKey
	var oldestKey telemetry.ProcessKey
	var oldestTime time.Time
	first := true

	for inst, v := range lt.instances {
		if first || v.StartTime.Before(oldestTime) {
			oldestInst = inst
			oldestKey = v.Key
			oldestTime = v.StartTime
			first = false
		}
	}

	if !first {
		delete(lt.instances, oldestInst)
		delete(lt.processes, oldestKey)
	}
}

// PruneExpired removes processes older than TTL.
func (lt *LineageTracker) PruneExpired(now time.Time) int {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	pruned := 0
	for inst, v := range lt.instances {
		if now.Sub(v.StartTime) > lt.ttl {
			delete(lt.instances, inst)
			delete(lt.processes, v.Key)
			pruned++
		}
	}
	return pruned
}
