# ContainerGuard

**Resilient eBPF-Based Runtime Intrusion Detection for Linux Containers**

ContainerGuard is a kernel-level runtime security monitoring and intrusion detection framework designed for Linux container environments. It directly addresses the critical research question:

> *Can a runtime security monitor reliably preserve, account for, and reconstruct security-relevant container activity when its telemetry pipeline experiences event pressure, lifecycle races, and incomplete observations?*

---

## Key Capabilities

1. **Stateful Container Attribution Engine:**
   - Overcomes the container startup race condition where eBPF syscall events arrive before container runtime inspection completes.
   - Formal attribution states: `PENDING`, `RESOLVED`, `UNRESOLVED`, `STALE_MAPPING`, `HOST_CONFIRMED`.
   - Bounded pending queue with configurable TTL and lifecycle-driven notification triggers.

2. **Telemetry Integrity & Event-Loss Accounting:**
   - Kernel-side atomic accounting maps tracking hook invocations, ring buffer reservation drops, and successfully submitted records.
   - Monotonic sequence numbers embedded in the kernel payload to mathematically detect event stream gaps in userspace.
   - Fine-grained userspace accounting distinguishing decode errors, queue drops, and lifecycle expiration.

3. **Container-Aware Process Lineage Reconstruction:**
   - Composite-keyed process tracking (`cgroup_id` + `tgid`) eliminating cross-container PID collisions and PID reuse ambiguities.
   - Retains parent-child execution graphs for forensic analysis.

4. **Deterministic Intrusion Detection Engine:**
   - Immediate detection of container breakouts (`nsenter`, `unshare`, `capsh`, `chroot`).
   - Execution from writable container mounts (`/tmp`, `/dev/shm`, `/var/tmp`).
   - Interactive shell execution inside containers.

---

## Architecture Overview

```
 [ Linux Kernel ]
  sys_enter_execve Tracepoint
         │
         ├──► telemetry_counters (BPF Array: Hooks, Drops, Submits)
         ├──► cgroup_event_counters (BPF Hash: per-cgroup counts)
         └──► BPF Ring Buffer (16 MB, Monotonic Sequence Numbers)
                    │
                    ▼
 [ ContainerGuard Userspace Engine ]
         │
         ├── Ingester (Fast Binary Unpacker, Sequence Gap Detector)
         │        │
         │        ▼
         ├── Attribution Buffer (Bounded Queue, State Machine: PENDING/RESOLVED)
         │        ▲
         │        │ Lifecycle updates / Reconcile
         │   Docker Container Resolver (cgroup v2 Inode Lookup)
         │        │
         │        ▼
         ├── Lineage Tracker (Composite Cgroup+PID Tree)
         │        │
         │        ▼
         ├── Deterministic Detection Engine (Breakout, Writable Exec, Shell Rules)
         │        │
         └── Storage & Telemetry Accounting Reporter (Structured JSON & Metrics)
```

---

## Directory Structure

- `bpf/`: eBPF C kernel probes with BTF and accounting maps.
- `cmd/containerguard/`: Daemon entry point with flags and graceful lifecycle management.
- `internal/collector/`: BPF loader, ring buffer reader, and kernel map poller.
- `internal/container/`: Docker Engine integration and cgroup v2 inode resolver.
- `internal/telemetry/`: Event schemas, fast decoders, and multi-tier accounting metrics.
- `internal/pipeline/`: Decoupled ingestion, bounded attribution buffer, and event dispatcher.
- `internal/lineage/`: Container-isolated process relationship reconstruction.
- `internal/detection/`: Deterministic security rule engine.
- `internal/storage/`: Structured event and alert JSON log writers.
- `scripts/`: Build and automated test runners.
- `docs/`: Technical audit reports, threat models, and architectural specifications.
