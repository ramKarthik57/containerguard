# ContainerGuard Engineering and Research Development Log

## Project Identification
- **Title:** ContainerGuard: Resilient eBPF-Based Runtime Intrusion Detection for Linux Containers
- **Repository:** `/home/ram/ebpf-smoke-test`
- **Environment:** Ubuntu 26.04 on WSL2 (Kernel 6.18.33.1-microsoft-standard-WSL2, x86_64), Go 1.26.8, Clang 21.1.8, Docker 29.9.3, containerd 2.4.2.

---

## Log Entries

### Entry 001 - 2026-11-07: Phase A Environment & Codebase Audit
- **Status:** Completed.
- **Actions:**
  1. Audited repository contents: verified `bpf-src/execve_events.c`, `execve_events.o`, `container.go`, `main.go`, `go.mod`.
  2. Verified compiler toolchain: Clang 21.1.8, bpftool 7.7.0, Go 1.26.8.
  3. Recompiled `bpf-src/execve_events.c` with exact flags (`-g -O2 -target bpf -I/usr/include/x86_64-linux-gnu`) and confirmed MD5 checksum `ab5edb56fc1787d2e7b6b92795d86805` matches `execve_events.o`.
  4. Tested Go compilation: verified `go build .` produces identical 12.9MB binary.
  5. Identified 5 key engineering defects and research gaps:
     - Container attribution race (events arriving before Docker lifecycle inspection finishes).
     - Silent kernel ring buffer drops without accounting maps.
     - Shutdown hang on blocking ringbuf read.
     - Synchronous head-of-line blocking pipeline.
     - Ambiguity between root host events and delayed container events.
  6. Initialized Git repository (`5199c92`) to maintain clean change control and provenance.
  7. Formulated modular target architecture conforming to Section 12 specifications.

### Entry 002 - 2026-11-07: Phase B, C, D, E Implementation & Verification
- **Status:** Completed.
- **Architectural Reorganization:**
  - Transitioned flat prototype into modular package hierarchy conforming to Section 12: `bpf/`, `cmd/containerguard/`, `internal/collector/`, `internal/container/`, `internal/telemetry/`, `internal/pipeline/`, `internal/lineage/`, `internal/detection/`, `internal/storage/`, `scripts/`, `docs/`.
- **eBPF Program Enhancements (`bpf/execve_events.c`):**
  - Added atomic accounting array map `telemetry_counters` (`CG_METRIC_HOOK_CALLS`, `CG_METRIC_RB_RESERVE_DROPS`, `CG_METRIC_RB_SUBMITTED`).
  - Added per-cgroup event count hash map `cgroup_event_counters`.
  - Added monotonic sequence number generator `event_sequence` (`seq_num`) in event payload for mathematical stream continuity verification.
  - Successfully compiled with Clang 21.1.8 into `bpf/execve_events.o`.
- **Attribution State Machine & Race Resolution (`internal/container` & `internal/pipeline`):**
  - Implemented 5 explicit attribution states: `PENDING`, `RESOLVED`, `UNRESOLVED`, `STALE_MAPPING`, `HOST_CONFIRMED`.
  - Implemented `AttributionBuffer` with bounded pending FIFO queue and $O(1)$ cgroup index for immediate resolution when Docker container registration occurs.
  - Implemented stale mapping cache (tombstones) to track events from containers that terminated during telemetry collection.
  - Implemented host root cgroup detection to prevent false-positive host attribution.
  - Eliminated shutdown hang defect by adding asynchronous reader closure on context cancellation.
- **Multi-Tier Telemetry Accounting (`internal/telemetry`):**
  - Separated kernel hook invocations, kernel ring buffer drops, submitted events, userspace records received, decoded, pending, resolved, unresolved, queue overflows, and sequence gaps.
- **Process Lineage & Deterministic Detection Engine (`internal/lineage` & `internal/detection`):**
  - Implemented composite cgroup+TGID process store preventing PID collision across containers.
  - Implemented deterministic detection rules:
    - `CG-RULE-001`: Privileged container breakout utility (`nsenter`, `unshare`, etc.).
    - `CG-RULE-002`: Writable directory execution (`/tmp`, `/dev/shm`).
    - `CG-RULE-003`: Interactive shell spawned inside container.
- **Verification & Testing (`scripts/test.sh`):**
  - Unit tests across all packages executed and passing with 100% success rate:
    - `internal/telemetry`: `TestDecodeRawExecEvent`, `TestTelemetryAccounting`.
    - `internal/container`: `TestContainerResolverAttribution`.
    - `internal/pipeline`: `TestAttributionRaceResolution`, `TestAttributionTTLExpiration`, `TestSequenceGapDetection`.
    - `internal/lineage`: `TestLineageTrackerPIDReuseAndIsolation`.
    - `internal/detection`: `TestDetectionRules`.
  - Static analysis: `go vet ./...` clean; `gofmt` applied across entire codebase.
  - Build script `scripts/build.sh` produces `bin/containerguard` and `bpf/execve_events.o`.

### Entry 003 - 2026-11-08: Process Identity Audit & Structured Key Correction
- **Status:** Completed.
- **Audited Items & Findings:**
  1. *Correction of Composite Process Key:*
     - The prior heuristic key `(cgroup_id << 32) ^ TGID` discarded the upper 32 bits of 64-bit cgroup IDs and failed to isolate successive processes reusing a TGID in the same cgroup.
     - Replaced with structured identity `telemetry.ProcessKey`:
       ```go
       type ProcessKey struct {
           CgroupID    uint64
           TGID        uint32
           StartTimeNS uint64
       }
       ```
     - Integrated `task_struct->start_time` and `real_parent` extraction via BPF CO-RE (`vmlinux.h` generated from `/sys/kernel/btf/vmlinux`).
     - Added parent instance tracking (`ParentKey`) preserving complete parent identity across process execution chains.
  2. *Audit of Host Attribution:*
     - Verified that unmapped cgroups are strictly placed into `PENDING` state and transition to `UNRESOLVED` upon timeout. They are never defaulted to `HOST_CONFIRMED`.
     - Added unit test `TestUnknownCgroupNeverClassifiedAsHost` verifying arbitrary cgroups cannot be misclassified as host.
  3. *Audit of Kernel Loss Counters & Per-Cgroup Map:*
     - Added `CG_METRIC_CGROUP_MAP_FAILS` (index 3) to `telemetry_counters` to explicitly count hash-map update failures.
     - Verified `bpf_ringbuf_reserve` failure accounting is atomic.
  4. *Audit of Monotonic Sequence Numbers:*
     - Implemented `SequenceTracker` with a sliding reorder window (1024 elements) to distinguish multi-core ring buffer commit reordering from genuine sequence drops.
  5. *Privilege Model Enforcement:*
     - Explicitly preserved existing privilege model: no passwordless sudo rules and no docker group modifications.
     - Authored reproducible live integration test runner `scripts/live_integration_test.sh` for user-authenticated execution context.
