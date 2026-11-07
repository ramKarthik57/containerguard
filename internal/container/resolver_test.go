package container

import (
	"testing"
	"time"

	"cg-smoke-test/internal/telemetry"
)

func TestContainerResolverAttribution(t *testing.T) {
	resolver := NewContainerResolver(nil)
	resolver.SetHostRootCgroup(1)

	// 1. Unmapped cgroup should return PENDING
	info, state := resolver.Resolve(100)
	if state != telemetry.AttributionPending {
		t.Errorf("expected state PENDING, got %s", state)
	}
	if info.ID != "" {
		t.Errorf("expected empty info, got %v", info)
	}

	// 2. Host root cgroup should return HOST_CONFIRMED
	info, state = resolver.Resolve(1)
	if state != telemetry.AttributionHostConfirmed {
		t.Errorf("expected state HOST_CONFIRMED, got %s", state)
	}
	if info.Name != "HOST" {
		t.Errorf("expected container name 'HOST', got %s", info.Name)
	}

	// 3. Register a container directly
	c1 := ContainerInfo{
		ID:         "container-alpha-123456",
		Name:       "cg-test-a",
		Image:      "alpine:latest",
		InitPID:    1234,
		CgroupPath: "/docker/container-alpha-123456",
		CgroupID:   100,
		CreatedAt:  time.Now(),
	}
	resolver.RegisterDirect(c1)

	// 4. Mapped cgroup should now return RESOLVED
	info, state = resolver.Resolve(100)
	if state != telemetry.AttributionResolved {
		t.Errorf("expected state RESOLVED, got %s", state)
	}
	if info.Name != "cg-test-a" {
		t.Errorf("expected container name 'cg-test-a', got %s", info.Name)
	}

	// 5. Remove container -> should transition to STALE_MAPPING
	resolver.Remove("container-alpha-123456")
	info, state = resolver.Resolve(100)
	if state != telemetry.AttributionStaleMapping {
		t.Errorf("expected state STALE_MAPPING, got %s", state)
	}
	if !info.IsStale {
		t.Errorf("expected IsStale to be true")
	}
}
