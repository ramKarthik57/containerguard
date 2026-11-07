package main

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
)

type ContainerInfo struct {
	ID         string
	Name       string
	Image      string
	InitPID    int
	CgroupPath string
}

type ContainerResolver struct {
	docker *mobyclient.Client

	mu          sync.RWMutex
	byCgroup    map[uint64]ContainerInfo
	byContainer map[string]uint64
}

func NewContainerResolver(
	docker *mobyclient.Client,
) *ContainerResolver {
	return &ContainerResolver{
		docker:      docker,
		byCgroup:    make(map[uint64]ContainerInfo),
		byContainer: make(map[string]uint64),
	}
}

func readCgroupPath(pid int) (string, error) {
	data, err := os.ReadFile(
		fmt.Sprintf("/proc/%d/cgroup", pid),
	)
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(line, ":", 3)

		if len(fields) == 3 && fields[0] == "0" {
			return fields[2], nil
		}
	}

	return "", fmt.Errorf("unified cgroup entry not found")
}

func cgroupInode(path string) (uint64, error) {
	if !strings.HasPrefix(path, "/") {
		return 0, fmt.Errorf("invalid cgroup path")
	}

	fullPath := "/sys/fs/cgroup" + path

	info, err := os.Stat(fullPath)
	if err != nil {
		return 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unable to read inode")
	}

	return stat.Ino, nil
}

func (r *ContainerResolver) inspect(
	ctx context.Context,
	id string,
) (ContainerInfo, uint64, error) {

	result, err := r.docker.ContainerInspect(
		ctx,
		id,
		mobyclient.ContainerInspectOptions{},
	)
	if err != nil {
		return ContainerInfo{}, 0, err
	}

	container := result.Container

	if container.State == nil ||
		!container.State.Running ||
		container.State.Pid <= 0 {
		return ContainerInfo{}, 0,
			fmt.Errorf("container is not running")
	}

	path, err := readCgroupPath(container.State.Pid)
	if err != nil {
		return ContainerInfo{}, 0, err
	}

	inode, err := cgroupInode(path)
	if err != nil {
		return ContainerInfo{}, 0, err
	}

	image := ""
	if container.Config != nil {
		image = container.Config.Image
	}

	return ContainerInfo{
		ID:         container.ID,
		Name:       strings.TrimPrefix(container.Name, "/"),
		Image:      image,
		InitPID:    container.State.Pid,
		CgroupPath: path,
	}, inode, nil
}

func (r *ContainerResolver) upsert(
	ctx context.Context,
	id string,
) error {

	info, inode, err := r.inspect(ctx, id)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if previous, ok := r.byContainer[info.ID]; ok {
		if previous != inode {
			delete(r.byCgroup, previous)
		}
	}

	r.byCgroup[inode] = info
	r.byContainer[info.ID] = inode

	log.Printf(
		"[resolver] mapped %s -> cgroup %d",
		info.Name,
		inode,
	)

	return nil
}

func (r *ContainerResolver) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	inode, ok := r.byContainer[id]
	if !ok {
		return
	}

	delete(r.byCgroup, inode)
	delete(r.byContainer, id)

	log.Printf(
		"[resolver] removed container mapping: %s",
		id,
	)
}

func (r *ContainerResolver) refresh(
	ctx context.Context,
) error {

	result, err := r.docker.ContainerList(
		ctx,
		mobyclient.ContainerListOptions{},
	)
	if err != nil {
		return err
	}

	nextCgroup := make(map[uint64]ContainerInfo)
	nextContainer := make(map[string]uint64)

	for _, item := range result.Items {
		info, inode, err := r.inspect(ctx, item.ID)
		if err != nil {
			log.Printf(
				"[resolver] cannot inspect %s: %v",
				item.ID[:min(12, len(item.ID))],
				err,
			)
			continue
		}

		nextCgroup[inode] = info
		nextContainer[info.ID] = inode
	}

	r.mu.Lock()
	r.byCgroup = nextCgroup
	r.byContainer = nextContainer
	r.mu.Unlock()

	log.Printf(
		"[resolver] inventory synchronized: %d running containers",
		len(nextCgroup),
	)

	return nil
}

func (r *ContainerResolver) Lookup(
	cgroupID uint64,
) (ContainerInfo, bool) {

	r.mu.RLock()
	defer r.mu.RUnlock()

	info, ok := r.byCgroup[cgroupID]
	return info, ok
}

func (r *ContainerResolver) handleEvent(
	ctx context.Context,
	event dockevents.Message,
) {

	if event.Type != dockevents.ContainerEventType {
		return
	}

	id := event.Actor.ID
	if id == "" {
		return
	}

	switch string(event.Action) {

	case "start", "restart", "unpause", "rename":

		callCtx, cancel := context.WithTimeout(
			ctx,
			5*time.Second,
		)
		defer cancel()

		if err := r.upsert(callCtx, id); err != nil {
			log.Printf(
				"[resolver] update failed for %s: %v",
				id[:min(12, len(id))],
				err,
			)
		}

	case "die", "stop", "destroy":

		r.remove(id)
	}
}

func (r *ContainerResolver) watch(ctx context.Context) {

	for ctx.Err() == nil {

		filters := make(mobyclient.Filters).
			Add("type", "container")

		stream := r.docker.Events(
			ctx,
			mobyclient.EventsListOptions{
				Filters: filters,
			},
		)

		// Start listening before taking the initial snapshot.
		// Events occurring during synchronization remain queued.
		if err := r.refresh(ctx); err != nil {
			log.Printf(
				"[resolver] initial synchronization failed: %v",
				err,
			)
		}

		log.Println("[resolver] Docker event stream active")

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

				r.handleEvent(ctx, event)

			case err, ok := <-errors:
				if !ok {
					errors = nil
					continue
				}

				if err != nil {
					log.Printf(
						"[resolver] Docker event stream error: %v",
						err,
					)
					messages = nil
					errors = nil
				}
			}
		}

		if ctx.Err() != nil {
			return
		}

		log.Println(
			"[resolver] reconnecting to Docker event stream in 2 seconds",
		)

		timer := time.NewTimer(2 * time.Second)

		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (r *ContainerResolver) Start(ctx context.Context) {
	go r.watch(ctx)
}
