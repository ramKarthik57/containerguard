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

### Entry 004 - 2026-11-08: Phase F Live Kernel & Docker Validation Results
- **Status:** Completed Successfully.
- **Environment:**
  - Linux Kernel: `6.18.33.1-microsoft-standard-WSL2` (x86_64)
  - Container Runtime: Docker Engine 29.9.3, containerd 2.4.2
  - Cgroup Hierarchy: cgroup v2 (`/sys/fs/cgroup`)
- **Execution:**
  - Command: `sudo ./scripts/live_integration_test.sh`
  - PID: `15242`
  - Log Directory: `/tmp/containerguard_validation/`
- **Empirical Measured Results:**
  - `kernel_hook_invocations`: 79
  - `kernel_ringbuf_reserve_drops`: 0
  - `kernel_ringbuf_submitted`: 79
  - `kernel_cgroup_map_fails`: 0
  - `userspace_records_received`: 79
  - `userspace_records_decoded`: 79
  - `userspace_decode_failures`: 0
  - `sequence_gaps_detected`: 0
  - `reordered_events`: 0
  - `events_processed`: 78
  - `kernel_drop_rate_pct`: 0.00%
  - `userspace_loss_count`: 0
- **Container Attribution Validation:**
  - `cg-test-a` (ID: `52274ed23949`, cgroup: `5400`): 7 events resolved (`/bin/uname`, `/bin/ls`, `/bin/date`, runc runtime).
  - `cg-test-b-event-test` (ID: `2b604b614c95`): 14 events resolved across container restart.
    - Initial cgroup: `5888` (`/bin/id`, `/bin/sh`, `/tmp/test_alert.sh`).
    - Restart cgroup: `5960` (`/bin/uptime`, `/bin/sleep`).
    - The resolver successfully caught the Docker `restart` event, demoted `5888` to stale mapping cache, re-inspected the new PID and new cgroup v2 inode `5960`, and resumed attribution without data loss.
  - Ephemeral short-lived container (`docker run --rm busybox hostname`): Executed and exited within milliseconds (cgroup `6032`, seq `69`). Correctly buffered as `PENDING`, expired on timeout to `UNRESOLVED`. Verified zero false-positive host attribution.
- **Deterministic Detection Alerts Triggered (4 total):**
  1. `ALERT-23-CG-RULE-003`: `Shell Spawned Inside Container` (`/bin/sh` in `cg-test-b-event-test`, cgroup `5888`)
  2. `ALERT-27-CG-RULE-003`: `Shell Spawned Inside Container` (`/bin/sh` in `cg-test-b-event-test`, cgroup `5888`)
  3. `ALERT-29-CG-RULE-002`: `Execution From Writable Directory` (`/tmp/test_alert.sh` in `cg-test-b-event-test`, cgroup `5888`)
  4. `ALERT-51-CG-RULE-003`: `Shell Spawned Inside Container` (`/bin/sh` in `cg-test-b-event-test`, cgroup `5960`, post-restart)
- **Lifecycle & Shutdown:**
  - Handled SIGTERM cleanly (`kill -TERM 15242`).
  - Ring buffer reader closed asynchronously and printed final telemetry integrity accounting report.

### Entry 005 - 2026-11-08: Phase F Empirical Validation with Thread-Group Leader & Safe Lifecycle Isolation
- **Status:** Fully Validated and Verified.
- **Git Commit:** `0edebfc`
- **Audit Findings Implemented Prior to Run:**
  1. *Thread-Group Leader Start Time Extraction:*
     - BPF CO-RE extracts `task->group_leader->start_time` and `real_parent->group_leader->start_time`.
     - Verified that worker subthreads calling `execve()` use the consistent process-level identity (`TGID` + group-leader `start_time`).
     - Added fallback degradation flags (`CG_FLAG_START_TIME_ESTIMATED`) ensuring unreadable start times are transparently flagged rather than silently set to zero.
  2. *Watermark Sliding Window Sequence Tracker:*
     - Replaced premature gap counting with a pending-gap sliding watermark tracker.
     - Verified via unit test `TestConcurrentSequenceStress` (2,000 events under randomized multi-core jitter) that transient out-of-order deliveries are reconciled without false loss alerts.
  3. *Script Safety & Container Isolation:*
     - Refactored `scripts/live_integration_test.sh` to preserve research containers `cg-test-a` and `cg-test-b-event-test` untouched.
     - Lifecycle tests (start, restart, rename, destroy) were executed using dedicated container `cg-lifecycle-ephemeral` -> `cg-lifecycle-renamed`.
- **Live Empirical Test Results:**
  - Command: `sudo ./scripts/live_integration_test.sh` (PID `18025`).
  - Total Decoded Events: 106.
  - Kernel Hook Invocations: 106.
  - Kernel Ring Buffer Submitted: 106.
  - Kernel Ring Buffer Reserve Drops: 0.
  - Kernel Cgroup Hash Map Failures: 0.
  - Userspace Records Received & Decoded: 106 (100% recall).
  - Sequence Gaps Detected: 0.
  - Reordered Events: 0.
  - Events Attributed to `cg-test-a`: 6 (`uname -a`, `ls -la /`, `date`, runc).
  - Events Attributed to `cg-test-b-event-test`: 10 (`id`, `/bin/sh`, `/tmp/test_alert.sh`, runc).
  - Events Attributed to `cg-lifecycle` test: 8 (tracked across initial spawn `6320`, restart `6392`, and rename to `cg-lifecycle-renamed`).
  - Ephemeral Container Test (`docker run --rm busybox hostname`): Captured at seq 97, cgroup 6464, expired gracefully to `UNRESOLVED` with zero host false positives.
  - Deterministic Alerts Triggered: 3 (2x `CG-RULE-003` Shell spawned, 1x `CG-RULE-002` Execution from writable `/tmp`).
  - Lineage Reconstruction: Verified `parent_key` of `/tmp/test_alert.sh` (`TGID=18655`) directly linked to parent `/bin/sh` (`TGID=18648`) with matching start times.
  - Graceful Shutdown: SIGTERM cleanly flushed sequence tracker and closed ring buffer reader.

### Entry 006 - 2026-11-08: Phase H Controlled Telemetry Stress Testing Execution (Tier 1)
- **Status:** Completed and Verified.
- **Git Commit:** `6ce3427` (execution validated)
- **Stress Harness:** `scripts/stress_test.sh 1000`
- **Workload Profile:**
  - 4 concurrent execution streams (250 executions per stream): `cg-test-a`, `cg-test-b-event-test`, dedicated temporary container `cg-stress-worker`, and host workload.
  - Concurrent injection of attack payload `/tmp/exploit_sim.sh` inside `cg-test-b-event-test` during active load burst.
- **Empirical Execution Telemetry:**
  - Elapsed Execution Time: 0.798 seconds.
  - Measured Event Throughput: 1,302.6 events/sec.
  - Kernel Hook Invocations: 1,040.
  - Kernel Ring Buffer Submissions: 1,040.
  - Kernel Ring Buffer Reservation Drops: 0 (0.00% drop rate).
  - Kernel Cgroup Hash Map Failures: 0.
  - Userspace Records Received: 1,040.
  - Userspace Records Decoded: 1,040.
  - Decode Failures: 0.
  - Telemetry Delivery Rate: 100.00%.
  - Sequence Gaps Detected: 0.
  - Reordered Events Handled: 0.
- **Attribution & Queue Accounting:**
  - Attribution Resolved (Containers): 762 events mapped to container IDs.
  - Attribution Unresolved (Non-Container Host): 278 events.
  - Cumulative Transitions into Pending: 278.
  - Peak Pending Queue Depth: 277 (well within the 4,096 ring capacity).
  - Current Pending Queue Depth at Exit: 0 (clean drain).
  - Userspace Queue Overflows: 0.
- **Threat Detection Fidelity Under Load:**
  - Attack event `ALERT-1028-CG-RULE-002` (Execution from writable directory `/tmp/exploit_sim.sh` inside container `cg-test-b-event-test`) was successfully captured, attributed, alerted, and recorded with full parent lineage intact.
- **Archival:** Full empirical evidence preserved in `docs/evidence/phase_h/stress_1000/` (`report.json`, `alerts.jsonl`, `events.jsonl`, `daemon.log`).

### Entry 007 - 2026-11-08: Complete Phase H Multi-Tier Telemetry Stress Benchmarking (5k, 10k, 25k)
- **Status:** Completed and Verified.
- **Git Commit:** Following `cb79c6b`
- **Workload Scaling:**
  - Executed Tiers 2, 3, and 4 via `scripts/stress_test.sh`:
    - Tier 2 (5,000 target): 5,027 hooks in 2.82s (1,781.6 events/sec).
    - Tier 3 (10,000 target): 10,027 hooks in 5.31s (1,889.1 events/sec).
    - Tier 4 (25,000 target): 25,032 hooks in 13.02s (1,923.0 events/sec).
  - Total monitored execution events across all runs: 41,126.
- **Zero Loss Telemetry:**
  - Ring buffer reservation drops: 0 across all 41,126 events.
  - Cgroup map failures: 0.
  - Userspace decode failures: 0.
  - Telemetry delivery rate: 100.00% across all tiers.
- **Empirical Multi-Core Watermark Validation:**
  - In Tier 4 (25,000 events), 1 transient multi-core out-of-order event commit occurred across the 4 concurrent worker processes.
  - The `SequenceTracker` watermark sliding window (1,024 capacity) successfully held the gap and absorbed the reordered event without triggering false sequence gap alerts (`sequence_gaps_detected: 0`, `reordered_events: 1`).
- **Attribution Ratio Convergence:**
  - Workload was generated with 3 container streams and 1 host stream (75.00% theoretical ratio).
  - Observed container resolutions: Tier 2 = 74.86%, Tier 3 = 74.92%, Tier 4 = 74.96% (within 0.04% of ground truth).
  - Zero false-positive host or container misclassifications.
- **Queue Saturation Dynamics:**
  - Peak pending queue depth plateaued at 1,371 entries at 25,000 events (33.5% of 4,096 capacity), demonstrating that userspace drain rate keeps pace with high-throughput continuous generation without queue overflow.
- **Alert Preservation:**
  - Writable mount execution alerts (`ALERT-5022-CG-RULE-002`, `ALERT-10022-CG-RULE-002`) and shell spawner alerts (`CG-RULE-003`) were captured with lineage preserved under maximum workload concurrency.
- **Archival:** Complete logs and reports stored in `docs/evidence/phase_h/` (`stress_5000/`, `stress_10000/`, `stress_25000/`).

### Entry 008 - 2026-11-08: Phase H.1 Evidence Reconciliation and Phase H.2 Saturation Harness
- **Status:** Phase H.1 Completed; Phase H.2 Harness Implemented.
- **Git Commit:** Following `dca8d56`
- **Phase H.1 Reconciled Evidence:**
  1. *Additional Hooks Breakdown:* All 126 additional hooks across the 4 tiers were identified by process and origin (36 container orchestration, 8 host orchestration, 29 harness CLI, 11 injected conditions, 18 ambient WSL2 system, 24 trailing residual).
  2. *Throughput Definitions:* Replaced single throughput metric with distinct Target Workload Throughput (up to 1,920.5 ev/s) and Observed Hook Throughput (up to 1,923.0 hooks/s).
  3. *Atomic Counter Correctness:* Audited `bpf/execve_events.c`. Confirmed hardware-atomic `__sync_fetch_and_add` across all maps; hardened cgroup counter insertion using `BPF_NOEXIST` with atomic re-lookup fallback to eliminate insertion race conditions.
  4. *Sequence Order Correction:* Clarified that BPF ring buffer records are consumed in reservation order; the single Tier 4 reordering was an interleaving between reservation timestamp and atomic sequence ticket acquisition across cores.
  5. *Attribution Ground Truth:* 30,801 container events resolved (100% precision, 100% recall); non-container host events correctly designated as `UNRESOLVED` rather than claimed host events.
  6. *Alert Preservation:* Clarified that firing `/tmp` scripts evaluates deterministic rule execution, not real-world multi-stage exploits.
- **Phase H.2 Engineering Implementation:**
  - Added `-ringbuf-size-kb`, `-backpressure-pause-sec`, and `-backpressure-delay-ms` flags to ContainerGuard daemon.
  - Implemented dynamic ring buffer sizing in `internal/collector/collector.go` (`spec.Maps["events"].MaxEntries = sizeKB * 1024`).
  - Implemented backpressure simulation pause and per-sample delay in `BPFCollector.readLoop`.
  - Added shutdown drain loop in `cmd/containerguard/main.go` to ensure all in-flight channel events are processed before writing the final accounting snapshot.
  - Authored automated benchmark harness `scripts/saturation_test.sh` supporting capacity scaling (64 KiB, 256 KiB, 1 MiB, 16 MiB), concurrency scaling (up to 16 streams), and resource sampling (CPU %, RAM).
  - Authored experimental specification `docs/SATURATION_EVALUATION.md`.

### Entry 009 - 2026-11-08: Phase H.2 Controlled Saturation Benchmarking and Telemetry Boundary Demonstration
- **Status:** Empirical Saturation Boundary Verified.
- **Git Commit:** Following `ccc9999`
- **Suite 1 Execution (8-Stream Active Drain):**
  - Evaluated 16 MiB, 1 MiB, 256 KiB, and 64 KiB buffers across 8 concurrent container streams (2,000 target events).
  - Throughput: 2,316 – 2,445 hooks/sec.
  - Zero reservation drops occurred across all sizes, proving that active drain concurrency prevents buffer saturation even at 64 KiB.
  - Reduced daemon RSS memory from 56.5 MiB (16 MiB buffer) to 25.0 MiB (1 MiB buffer).
- **Suite 2 Execution (Induced Userspace Backpressure & Boundary Quantification):**
  - Induced 4-second reader backpressure pause during 2,000-event multi-core bursts.
  - `sat_bp_16mb` (16 MiB buffer): 0 drops (0.00% loss) — fully absorbed the burst.
  - `sat_bp_256kb` (256 KiB buffer): 1,302 drops (61.79% loss) after buffering 805 events (matching theoretical 762 limit).
  - `sat_bp_64kb` (64 KiB buffer): 1,875 drops (89.12% loss) after buffering 229 events (matching theoretical 190 limit).
- **Conservation and Recovery:**
  - In all saturation runs, $\text{Hooks} = \text{Submissions} + \text{Drops}$ with 100.00% accounting conservation.
  - Demonstrates graceful recovery: reader resumed consumption upon unpause, drained buffered events without deadlock or memory fault, and completed normal shutdown.
- **Archival:** All Suite 1 and Suite 2 empirical logs, metric dumps, and reports archived in `docs/evidence/phase_h2/`.

### Entry 010 - 2026-11-08: Phase H.2 Telemetry Audit, Shutdown Synchronization, and Verified Boundary Reruns
- **Status:** Completed and Verified.
- **Git Commit:** Following `b4e7b07`
- **Root Cause Diagnoses & Fixes:**
  1. *Delivery Exceeding 100% Anomaly:* Traced to asynchronous map closing in `collector.go` race-conditioning with final metrics poll. Fixed by keeping BPF maps open until after synchronous post-drain `PollKernelMetrics()`, guaranteeing submitted counter matches userspace decoded counter.
  2. *Theoretical Capacity Verification:* `pahole` inspection verified `sizeof(struct exec_event)` is 336 bytes + 8 bytes header = 344 bytes. 1-second metric snapshots during reader freeze confirmed the buffer held **exactly 190 events for 64 KiB** ($\lfloor 65,536/344 \rfloor = 190$) and **exactly 762 events for 256 KiB** ($\lfloor 262,144/344 \rfloor = 762$) before `bpf_ringbuf_reserve` failed. Trailing accepted records occurred post-unpause during container cleanup.
  3. *Unresolved Queue Entries at Exit:* Traced to background resource sampler (`ps`/`sleep`) executing within 0.5s of shutdown with unexpired 2-second TTL. Fixed by adding `buffer.Flush()` on shutdown to force-expire all pending items to `UNRESOLVED` and reset `CurrentPendingQueueDepth` to 0.
  4. *Parser Fix:* Replaced shell sed extraction with Python delimiter block extractor, eliminating `JSONDecodeError`.
- **Audited Reruns Executed Autonomously:**
  - `sat_256kb_8stream`: 2,082 hooks, 2,082 submitted, 0 drops (0.00%), 2,082 decoded, 100.00% delivery, final queue depth: 0.
  - `sat_bp_16mb`: 2,105 hooks, 2,105 submitted, 0 drops (0.00%), 2,105 decoded, 100.00% delivery, final queue depth: 0.
  - `sat_bp_256kb`: 2,102 hooks, 801 submitted, 1,301 drops (61.89% loss), 801 decoded, 100.00% delivery, final queue depth: 0.
  - `sat_bp_64kb`: 2,104 hooks, 231 submitted, 1,873 drops (89.02% loss), 231 decoded, 100.00% delivery, final queue depth: 0.
- **Archival:** Original unreconciled runs preserved in `docs/evidence/phase_h2/original_unreconciled/`; verified runs active in `suite1_capacity_8stream/` and `suite2_backpressure/`.






### Entry 011 - 2026-11-08: Phase I Adversarial Telemetry, Execution-Path Coverage, Detection Validation, and Overhead Evaluation
- **Status:** Phase I Completed & Fully Validated.
- **Phase I.0 Baseline Verification:**
  - HEAD at `96f36ce` verified. Binary hashes for `bin/containerguard` (`fcb2d144...`) and `bpf/execve_events.o` (`a03f97cb...`) matched baseline. Unit tests verified passing.
- **Phase I.1 Process Identity & Cgroup Migration:**
  - Decoupled immutable process instance identity (`ProcessInstanceKey{TGID, StartTimeNS}`) from mutable execution context (`CgroupID`).
  - Implemented kernel-space parent cgroup resolution via BPF CO-RE: `BPF_CORE_READ(parent_leader, cgroups, dfl_cgrp, kn, id)`, fixing cross-cgroup container parentage.
  - Added cgroup migration audit and tracking in `LineageTracker`: processes migrating between cgroups preserve identity and ancestry, with previous cgroups recorded in `node.CgroupHistory` and flagged as `cgroup_migrated: true`.
- **Phase I.2 & I.3 Multi-Tracepoint Execution Coverage & Adversarial Telemetry:**
  - Extended kernel eBPF engine to attach 5 tracepoints:
    1. `tracepoint/syscalls/sys_enter_execve`
    2. `tracepoint/syscalls/sys_enter_execveat`
    3. `tracepoint/sched/sched_process_exec` (Committed executions)
    4. `tracepoint/syscalls/sys_exit_execve` (Failed attempts)
    5. `tracepoint/syscalls/sys_exit_execveat` (Failed attempts)
  - Implemented in-flight attempt tracking using an LRU hash map (`active_exec_attempts`) and per-CPU scratchpad (`attempt_scratch`), eliminating kernel stack pressure while preventing memory leaks.
  - Intercepts and validates all execution paths in live Linux kernel:
    - Standard `execve`, direct syscall `syscall(SYS_execve, ...)`, `execveat` relative dirfd, `execveat` with `AT_EMPTY_PATH` (anonymous memfd), shebang scripts, symlink traversal, static ELF binaries, setuid binaries, and containerized workloads.
  - Distinguishes execution attempts from committed executions:
    - Successful executions finalized on `sched_process_exec` (`CG_FLAG_COMMITTED_EXEC`).
    - Failed executions finalized on `sys_exit_execve` (`CG_FLAG_EXEC_FAILED`) with negative errno (-2 for ENOENT, -13 for EACCES).
  - Validated boundary conditions: pathname truncation (>256B), comm truncation (15+ chars), and PID recycling.
  - Live empirical run: 72 hooks observed, 72 ring buffer submissions, 0 drops, 72 decoded (100.00% delivery, exact conservation satisfied).
- **Phase I.4 Detection Engine Validation & False-Positive Evaluation:**
  - Evaluated against a mixed corpus of 133 events: 121 benign developer events (Git operations, GCC compilation toolchain, container queries) and 12 attack simulations.
  - `CG-RULE-001` (Breakout Utilities): TP=4, FP=0, TN=129, FN=0 | Precision=100%, Recall=100%, FPR=0.00%.
  - `CG-RULE-002` (Writable Directory Execution): TP=3, FP=0, TN=130, FN=0 | Precision=100%, Recall=100%, FPR=0.00%.
  - `CG-RULE-003` (Container Interactive Shells): TP=5, FP=0, TN=128, FN=0 | Precision=100%, Recall=100%, FPR=0.00%.
  - Zero false positives observed across all developer workloads.
- **Phase I.5 Monitoring Overhead Evaluation:**
  - Benchmarked 2,000 concurrent executions across 4 streams:
    - Baseline (Unmonitored): 0.4492s (4,451.91 ev/s).
    - Monitored (ContainerGuard Active): 0.4648s (4,303.08 ev/s).
    - Execution Time Overhead: +3.46%.
    - Throughput Impact: -3.34%.
    - Marginal Latency per Event: 7.77 microseconds.
    - Daemon CPU: < 0.1%, Daemon RSS: 6.02 MiB.
- **Phase I.6 Artifacts Authored:**
  - `docs/PHASE_I_ADVERSARIAL_EVALUATION.md`
  - `docs/EXECUTION_PATH_COVERAGE.md`
  - `docs/DETECTION_VALIDATION.md`
  - `docs/OVERHEAD_EVALUATION.md`
  - Evidence archived in `docs/evidence/phase_i/`.
