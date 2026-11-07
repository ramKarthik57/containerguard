# ContainerGuard System Architecture

## 1. Design Principles

1. **Decoupled Telemetry Pipeline:** The kernel event ingestion loop must never perform synchronous network, disk, or container runtime calls. Draining the kernel BPF Ring Buffer is isolated from container identity resolution and downstream alerting.
2. **Explicit State Over Default Assumptions:** Unmapped events are never prematurely categorized as host events. They transition through an explicit attribution state machine.
3. **Multi-Tier Loss Accounting:** Drops occurring at the kernel boundary (ring buffer full) are accounted for separately from userspace queue drops and decode failures.
4. **Deterministic Security Logic:** Core security decisions and detection rules are strictly deterministic, transparent, and defensible without nondeterministic models.

---

## 2. Core Subsystems

### A. Kernel eBPF Telemetry (`bpf/execve_events.c`)
- **Hook Point:** `tracepoint/syscalls/sys_enter_execve`.
- **Maps:**
  - `events`: 16 MB BPF Ring Buffer (`BPF_MAP_TYPE_RINGBUF`).
  - `telemetry_counters`: 3-entry array tracking `HOOK_INVOCATIONS`, `RINGBUF_RESERVE_DROPS`, and `SUBMITTED_EVENTS`.
  - `cgroup_event_counters`: Hash map tracking per-cgroup execution counts.
  - `event_sequence`: Monotonic sequence counter generating `seq_num` for stream integrity validation.

### B. Container Identity Resolution (`internal/container`)
- Obtains the host root cgroup inode (`/sys/fs/cgroup`) at startup.
- Connects to Docker Engine via Unix socket (`/var/run/docker.sock`).
- Reconciles active containers by inspecting container PIDs and reading `/proc/<pid>/cgroup` to locate the unified cgroup v2 inode.
- Maintains active and tombstoned mappings to support delayed attribution.

### C. Attribution & Ingestion Pipeline (`internal/pipeline`)
- **Ingester:** Fast binary decoder verifying sequence continuity.
- **AttributionBuffer:**
  - Maintains a bounded chronological queue of `PENDING` events.
  - Implements an index by `cgroup_id` for $O(1)$ fast resolution when container startup events arrive.
  - Sweeps stale items using configurable `PendingTTL` (default 2s), promoting unmapped events to `UNRESOLVED`.

### D. Process Lineage & Detection (`internal/lineage` & `internal/detection`)
- Identifies processes via composite keys `(cgroupID << 32) ^ TGID`, avoiding PID reuse collision.
- Evaluates deterministic security rules:
  - `CG-RULE-001`: Container breakout utilities (`nsenter`, `unshare`, `capsh`, `chroot`).
  - `CG-RULE-002`: Execution from writable directories (`/tmp`, `/dev/shm`).
  - `CG-RULE-003`: Interactive shells inside containers.
