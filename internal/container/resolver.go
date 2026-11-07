package container

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	dockevents "github.com/moby/moby/api/types/events"
	mobyclient "github.com/moby/moby/client"

	"cg-smoke-test/internal/telemetry"
)

// ContainerResolver manages concurrent cgroup-to-container identity mappings.
type ContainerResolver struct {
	docker DockerEngineClient

	mu             sync.RWMutex
	byCgroup       map[uint64]ContainerInfo
	byContainer    map[string]uint64
	staleMappings  map[uint64]ContainerInfo // Retained tombstones for graceful stale mapping detection
	hostRootCgroup uint64

	updateChan chan MappingUpdate
}

// NewContainerResolver constructs a resolver and determines the host root cgroup inode.
func NewContainerResolver(docker DockerEngineClient) *ContainerResolver {
	rootCgroup, err := getRootCgroupInode()
	if err != nil {
		log.Printf("[resolver] warning: could not determine host root cgroup inode: %v", err)
	}

	return &ContainerResolver{
		docker:         docker,
		byCgroup:       make(map[uint64]ContainerInfo),
		byContainer:    make(map[string]uint64),
		staleMappings:  make(map[uint64]ContainerInfo),
		hostRootCgroup: rootCgroup,
		updateChan:     make(chan MappingUpdate, 256),
	}
}

// Updates returns the notification channel for mapping changes.
func (r *ContainerResolver) Updates() <-chan MappingUpdate {
	return r.updateChan
}

// HostRootCgroup returns the verified host root cgroup inode.
func (r *ContainerResolver) HostRootCgroup() uint64 {
	return r.hostRootCgroup
}

// SetHostRootCgroup allows overriding host root cgroup for testing.
func (r *ContainerResolver) SetHostRootCgroup(cgroup uint64) {
	r.hostRootCgroup = cgroup
}

func getRootCgroupInode() (uint64, error) {
	info, err := os.Stat("/sys/fs/cgroup")
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat conversion failed")
	}
	return stat.Ino, nil
}

// ReadCgroupPath extracts the unified cgroup v2 relative path for a given process PID.
func ReadCgroupPath(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) == 3 && fields[0] == "0" {
			return fields[2], nil
		}
	}

	return "", fmt.Errorf("unified cgroup entry not found for pid %d", pid)
}

// CgroupInode looks up the inode corresponding to a cgroup v2 relative path.
func CgroupInode(path string) (uint64, error) {
	if !strings.HasPrefix(path, "/") {
		return 0, fmt.Errorf("invalid cgroup path: %s", path)
	}

	fullPath := "/sys/fs/cgroup" + path
	info, err := os.Stat(fullPath)
	if err != nil {
		return 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unable to read inode for %s", fullPath)
	}

	return stat.Ino, nil
}

// Inspect fetches container details, PID, and cgroup inode.
func (r *ContainerResolver) Inspect(ctx context.Context, id string) (ContainerInfo, uint64, error) {
	result, err := r.docker.ContainerInspect(ctx, id, mobyclient.ContainerInspectOptions{})
	if err != nil {
		return ContainerInfo{}, 0, err
	}

	c := result.Container
	if c.State == nil || !c.State.Running || c.State.Pid <= 0 {
		return ContainerInfo{}, 0, fmt.Errorf("container %s is not running", id)
	}

	path, err := ReadCgroupPath(c.State.Pid)
	if err != nil {
		return ContainerInfo{}, 0, fmt.Errorf("cgroup path read failed: %w", err)
	}

	inode, err := CgroupInode(path)
	if err != nil {
		return ContainerInfo{}, 0, fmt.Errorf("cgroup inode lookup failed: %w", err)
	}

	image := ""
	if c.Config != nil {
		image = c.Config.Image
	}

	name := strings.TrimPrefix(c.Name, "/")
	info := ContainerInfo{
		ID:         c.ID,
		Name:       name,
		Image:      image,
		InitPID:    c.State.Pid,
		CgroupPath: path,
		CgroupID:   inode,
		CreatedAt:  time.Now().UTC(),
	}

	return info, inode, nil
}

// Upsert adds or updates a container mapping and broadcasts the update.
func (r *ContainerResolver) Upsert(ctx context.Context, id string) error {
	info, inode, err := r.Inspect(ctx, id)
	if err != nil {
		return err
	}

	r.mu.Lock()
	if prevInode, exists := r.byContainer[info.ID]; exists && prevInode != inode {
		// Retain old mapping in stale map for in-flight telemetry
		if prevInfo, ok := r.byCgroup[prevInode]; ok {
			prevInfo.IsStale = true
			r.staleMappings[prevInode] = prevInfo
		}
		delete(r.byCgroup, prevInode)
	}

	// Remove from stale if re-assigned
	delete(r.staleMappings, inode)

	r.byCgroup[inode] = info
	r.byContainer[info.ID] = inode
	r.mu.Unlock()

	log.Printf("[resolver] mapped container '%s' (%s) -> cgroup %d (path: %s)", info.Name, info.ID[:min(12, len(info.ID))], inode, info.CgroupPath)

	select {
	case r.updateChan <- MappingUpdate{ContainerID: info.ID, CgroupID: inode, Action: "start", Info: info}:
	default:
	}

	return nil
}

// RegisterDirect directly registers a mapping (useful for testing and manual registration).
func (r *ContainerResolver) RegisterDirect(info ContainerInfo) {
	r.mu.Lock()
	r.byCgroup[info.CgroupID] = info
	r.byContainer[info.ID] = info.CgroupID
	delete(r.staleMappings, info.CgroupID)
	r.mu.Unlock()

	select {
	case r.updateChan <- MappingUpdate{ContainerID: info.ID, CgroupID: info.CgroupID, Action: "start", Info: info}:
	default:
	}
}

// Remove cleans up a container mapping, moving it to stale mappings temporarily.
func (r *ContainerResolver) Remove(id string) {
	r.mu.Lock()
	inode, exists := r.byContainer[id]
	if !exists {
		r.mu.Unlock()
		return
	}

	if info, ok := r.byCgroup[inode]; ok {
		info.IsStale = true
		r.staleMappings[inode] = info
	}

	delete(r.byCgroup, inode)
	delete(r.byContainer, id)
	r.mu.Unlock()

	log.Printf("[resolver] container unmapped: %s (cgroup %d moved to stale cache)", id[:min(12, len(id))], inode)

	select {
	case r.updateChan <- MappingUpdate{ContainerID: id, CgroupID: inode, Action: "stop"}:
	default:
	}
}

// Resolve looks up a cgroup ID and assigns an explicit attribution state.
func (r *ContainerResolver) Resolve(cgroupID uint64) (ContainerInfo, telemetry.AttributionState) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 1. Check active container mappings
	if info, ok := r.byCgroup[cgroupID]; ok {
		return info, telemetry.AttributionResolved
	}

	// 2. Check if it matches host root cgroup
	if r.hostRootCgroup != 0 && cgroupID == r.hostRootCgroup {
		return ContainerInfo{
			ID:         "host",
			Name:       "HOST",
			CgroupPath: "/",
			CgroupID:   cgroupID,
		}, telemetry.AttributionHostConfirmed
	}

	// 3. Check recently stopped/stale container mappings
	if info, ok := r.staleMappings[cgroupID]; ok {
		return info, telemetry.AttributionStaleMapping
	}

	// 4. Default: Unresolved at this instant, pending lifecycle resolution
	return ContainerInfo{}, telemetry.AttributionPending
}

// Refresh re-syncs the entire container inventory from Docker.
func (r *ContainerResolver) Refresh(ctx context.Context) error {
	result, err := r.docker.ContainerList(ctx, mobyclient.ContainerListOptions{})
	if err != nil {
		return err
	}

	nextCgroup := make(map[uint64]ContainerInfo)
	nextContainer := make(map[string]uint64)

	for _, item := range result.Items {
		info, inode, err := r.Inspect(ctx, item.ID)
		if err != nil {
			log.Printf("[resolver] inspect failed for %s: %v", item.ID[:min(12, len(item.ID))], err)
			continue
		}
		nextCgroup[inode] = info
		nextContainer[info.ID] = inode
	}

	r.mu.Lock()
	// Stale detection for removed containers
	for id, oldInode := range r.byContainer {
		if _, stillRunning := nextContainer[id]; !stillRunning {
			if oldInfo, ok := r.byCgroup[oldInode]; ok {
				oldInfo.IsStale = true
				r.staleMappings[oldInode] = oldInfo
			}
		}
	}
	r.byCgroup = nextCgroup
	r.byContainer = nextContainer
	count := len(nextCgroup)
	r.mu.Unlock()

	log.Printf("[resolver] inventory reconciled: %d active containers", count)
	return nil
}

// HandleEvent processes individual Docker container lifecycle events.
func (r *ContainerResolver) HandleEvent(ctx context.Context, event dockevents.Message) {
	if event.Type != dockevents.ContainerEventType {
		return
	}

	id := event.Actor.ID
	if id == "" {
		return
	}

	switch string(event.Action) {
	case "start", "restart", "unpause", "rename":
		callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		if err := r.Upsert(callCtx, id); err != nil {
			log.Printf("[resolver] update failed for %s (action: %s): %v", id[:min(12, len(id))], event.Action, err)
		}
	case "die", "stop", "destroy":
		r.Remove(id)
	}
}

// Watch starts the Docker event stream listener and handles auto-reconnection and inventory reconciliation.
func (r *ContainerResolver) Watch(ctx context.Context) {
	for ctx.Err() == nil {
		filters := make(mobyclient.Filters).Add("type", "container")
		stream := r.docker.Events(ctx, mobyclient.EventsListOptions{Filters: filters})

		// Perform initial inventory reconciliation
		if err := r.Refresh(ctx); err != nil {
			log.Printf("[resolver] initial reconciliation failed: %v", err)
		}

		log.Println("[resolver] Docker lifecycle event monitor running")

		messages := stream.Messages
		errors := stream.Err

		for messages != nil || errors != nil {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-messages:
				if !ok {
					messages = nil
					continue
				}
				r.HandleEvent(ctx, event)
			case err, ok := <-errors:
				if !ok {
					errors = nil
					continue
				}
				if err != nil {
					log.Printf("[resolver] event stream error: %v", err)
					messages = nil
					errors = nil
				}
			}
		}

		if ctx.Err() != nil {
			return
		}

		log.Println("[resolver] reconnecting to Docker event stream in 2s...")
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// Start begins background lifecycle monitoring.
func (r *ContainerResolver) Start(ctx context.Context) {
	go r.Watch(ctx)
}
