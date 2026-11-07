package container

import (
	"context"
	"time"

	dockevents "github.com/moby/moby/api/types/events"
	mobyclient "github.com/moby/moby/client"
)

// ContainerInfo encapsulates container identity and metadata.
type ContainerInfo struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Image      string    `json:"image"`
	InitPID    int       `json:"init_pid"`
	CgroupPath string    `json:"cgroup_path"`
	CgroupID   uint64    `json:"cgroup_id"`
	CreatedAt  time.Time `json:"created_at"`
	IsStale    bool      `json:"is_stale,omitempty"`
}

// DockerEngineClient abstracts Docker operations for production and mock testing.
type DockerEngineClient interface {
	ContainerInspect(ctx context.Context, containerID string, options mobyclient.ContainerInspectOptions) (mobyclient.ContainerInspectResult, error)
	ContainerList(ctx context.Context, options mobyclient.ContainerListOptions) (mobyclient.ContainerListResult, error)
	Events(ctx context.Context, options mobyclient.EventsListOptions) mobyclient.EventsResult
	Close() error
}

// Ensure the moby client satisfies DockerEngineClient.
var _ DockerEngineClient = (*mobyclient.Client)(nil)

// MappingUpdate represents an update notification when a container mapping changes.
type MappingUpdate struct {
	ContainerID string
	CgroupID    uint64
	Action      dockevents.Action
	Info        ContainerInfo
}
