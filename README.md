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


---

## Verified Research Findings (Kernel 6.18 WSL2)

ContainerGuard was validated live against active Docker workloads (`cg-test-a`, `cg-test-b-event-test`) and multi-tier stress testing harnesses:
- **Telemetry Throughput Scaling:** Sustained up to 1,920.5 target events/sec (1,923.0 observed hooks/sec) across 4 concurrent container/host worker streams with 100.00% telemetry delivery and 0 ring buffer reservation drops across 41,126 total execution events.
- **Evidence Reconciliation & Accounting:** Reconciled 100% of non-target hooks down to container orchestration, harness CLI, and ambient system events.
- **Dynamic Cgroup Migration on Restart:** Proven across container restart (cgroup inode `5888` -> `5960` and `6320` -> `6392`) with seamless tombstone caching and attribution handover.
- **Thread-Group Leader Identity:** Eliminates multithreaded PID and start-time skew by querying `task->group_leader->start_time` via BPF CO-RE.
- **Deterministic Detection Under Pressure:** Preserved all security test alerts (including `/tmp` executable launches `CG-RULE-002` and shell spawns `CG-RULE-003`) and full parent lineage during high-throughput execution bursts.
- **Controlled Saturation Testing:** Phase H.2 benchmark harness (`scripts/saturation_test.sh`) maps the empirical telemetry loss boundary: 64 KiB drops 89.02% of events under backpressure (exact 190-event theoretical capacity limit), 256 KiB drops 61.89% (exact 762-event capacity limit), and 16 MiB absorbs the burst with 0% loss, satisfying $\text{Hooks} = \text{Submissions} + \text{Drops}$ with 100.00% precision.
- **Multi-Tracepoint Execution Coverage (Phase I):** 5 kernel tracepoints (`sys_enter_execve`, `sys_enter_execveat`, `sched_process_exec`, `sys_exit_execve`, `sys_exit_execveat`) covering standard `execve`, raw syscalls, relative `execveat`, anonymous `memfd` (`AT_EMPTY_PATH`), shebang scripts, symlinks, static ELFs, setuid binaries, and distinguishing execution attempts from committed executions with exact failure errno accounting.
- **Process Identity Decoupling & Cgroup Migration (Phase I):** Separates immutable `ProcessInstanceKey{TGID, StartTimeNS}` from mutable cgroups. Resolves parent cgroups independently via BPF CO-RE, preserving process lineage across cgroup migrations with previous cgroups recorded in history.
- **Detection Validation & Low Overhead (Phase I):** Evaluated against a mixed corpus of 133 events (121 benign developer events from Git, GCC compilation, container diagnostics vs 12 attack simulations). Achieved **100.00% Precision, 100.00% Recall, and 0.00% False Positive Rate** across `CG-RULE-001`, `CG-RULE-002`, and `CG-RULE-003`. Introduces only **+3.46% execution time overhead (7.77 microseconds per syscall)** with 6.02 MiB RSS memory footprint.


