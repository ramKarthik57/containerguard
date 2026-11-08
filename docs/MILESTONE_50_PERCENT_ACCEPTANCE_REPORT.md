# ContainerGuard: 50% Development Milestone Acceptance & Verification Report

**Release Label:** `ContainerGuard-50-Percent-Verified-Milestone`  
**Evaluation Date:** 2026-11-08  
**Environment:** Ubuntu 26.04.1 LTS on WSL2 (`Linux 6.18.33.1-microsoft-standard-WSL2`, x86_64, PREEMPT_DYNAMIC)  
**Compiler Toolchain:** Go 1.26.8, Clang 21.1.8, Docker Engine 29.9.3, containerd 2.4.2  
**Final Binary SHA-256 Checksums:**
- `bin/containerguard`: `cfee0d9675b653fdd7cda2629454a4839b1fd59ede0ba43f8bcd7ce7bebc93d0`
- `bpf/execve_events.o`: `6ae519a012694f11c9ab514c1b13cafb4b8551fb8deadaf10dee817862717ef3`
- `bin/test_exec_paths`: `37890b6bbc638c6066609afbd2cc98cfcb3ca70cd996385a44e4728f1459a32f`
- `bin/cg_setuid_test`: `b11b8709bfa3e4038ecfe7705500c9733be248e168af7991ae6e170c01596a95`

---

## 1. Executive Summary & Mandatory Scope Freeze

ContainerGuard has achieved its designated **50% development milestone gate**. Per project directives, all feature expansion, architecture extension, and Phase II work are strictly frozen. This report presents the comprehensive audit, verification evidence, regression outcomes, and known operational boundaries for all 16 components comprising the verified 50% scope.

---

## 2. Component-by-Component Acceptance Matrix

| # | Milestone Component | Implementation Artifacts | Verification Method | Empirical Outcome | Acceptance Verdict |
| :- | :--- | :--- | :--- | :--- | :--- |
| **1** | **eBPF Kernel Event Collection** | `bpf/execve_events.c` | Verifier check, `bpftool`, live tracepoint attach | 5 tracepoints attached, zero verifier rejections | **ACCEPTED** |
| **2** | **Execve & Execveat Monitoring** | `bpf/execve_events.c`, `collector.go` | `scripts/execution_path_test.sh` | Standard execve, direct syscall, execveat (dfd & relative paths) intercepted | **ACCEPTED** |
| **3** | **Success vs Failed Exec Differentiation** | `bpf/execve_events.c`, `event.go` | Failed exec harness (ENOENT = -2, EACCES = -13) | Finalized on `sched_process_exec` (success) vs `sys_exit_execve` (failure with errno) | **ACCEPTED** |
| **4** | **Ring Buffer & Kernel Loss Accounting** | `bpf/execve_events.c` (`telemetry_counters`) | `scripts/saturation_test.sh` under 4s backpressure | Exact conservation: $\text{Hooks} = \text{Submits} + \text{Drops}$; drops accurately counted | **ACCEPTED** |
| **5** | **Userspace Ingestion & Decoding** | `internal/pipeline/ingester.go`, `event.go` | Fast binary unpacker, `go test -race` | 0 decode failures across 45,000+ benchmark events | **ACCEPTED** |
| **6** | **Container Discovery & Attribution** | `internal/container/resolver.go` | Docker API + cgroup v2 inode mapping | 100% precision & recall against active baseline containers (`cg-test-a`, `cg-test-b`) | **ACCEPTED** |
| **7** | **Container Lifecycle Reconciliation** | `internal/container/resolver.go`, `attribution_buffer.go` | Dedicated lifecycle ephemeral test (`live_integration_test.sh`) | Container restart (cgroup inode rotation) & rename handled via tombstone cache | **ACCEPTED** |
| **8** | **Process Identity & Lineage** | `internal/lineage/lineage.go`, `event.go` | Process leader start time, multi-thread test | `ProcessInstanceKey{TGID, StartTimeNS}` invariant to PID reuse and cgroup shifts | **ACCEPTED** |
| **9** | **Cgroup Migration Handling** | `internal/lineage/lineage.go`, `bpf/execve_events.c` | Live cgroup migration between `/sys/fs/cgroup/cg_mig_*` | Process lineage unified under single node; `CgroupHistory` and `cgroup_migrated: true` logged | **ACCEPTED** |
| **10**| **Metadata & Path Truncation Handling** | `bpf/execve_events.c`, `event.go` | Path > 350B, comm 16B in `test_exec_paths` | `path_truncated: true` (null-terminated), `comm_truncated: true` | **ACCEPTED** |
| **11**| **Deterministic Detection Rules** | `internal/detection/engine.go` | Labelled corpus (Dataset 1: 121 benign + 12 attack = 133 events; Dataset 2: 120 benign + 12 attack = 132 events) | 100% Precision, 100% Recall, 0.00% FPR across `CG-RULE-001`, `002`, `003` | **ACCEPTED** |
| **12**| **Bounded Queue & Graceful Shutdown** | `internal/pipeline/attribution_buffer.go`, `main.go` | Bounded pending queue (daemon default capacity: 10,000 per `DefaultConfig().MaxPendingCapacity`; tested peak depth: 1,371) | Buffer flushed on SIGTERM; final queue depth = 0 in all benchmarks | **ACCEPTED** |
| **13**| **Telemetry Integrity & Saturation** | `scripts/saturation_test.sh`, `stress_test.sh` | 64 KiB, 256 KiB, 1 MiB, 16 MiB backpressure tests | Theoretical limits verified (64KB holds 190 events, 256KB holds 762 events before drop) | **ACCEPTED** |
| **14**| **Execution-Path Coverage** | `cmd/test_exec_paths/main.c`, `scripts/execution_path_test.sh` | 12 execution pathways tested | All 12 execution paths verified in live Linux kernel | **ACCEPTED** |
| **15**| **Detection & False-Positive Evaluation**| `scripts/detection_benchmark.sh` | Git operations, GCC build, container utilities | Zero false positives on host development activities | **ACCEPTED** |
| **16**| **Performance & Resource Overhead** | `scripts/overhead_benchmark.sh` | 2,000-event concurrent workload | +5.95% wall-clock overhead, 0.75% CPU, 6.04 MiB RSS | **ACCEPTED** |

---

## 3. Critical Correctness Checks & Empirical Verification

### 3.1 Telemetry Invariant Conservation
Across all test suites, the kernel accounting invariant was strictly enforced:
$$\text{Kernel Hook Invocations} = \text{Ring Buffer Submissions} + \text{Ring Buffer Reservation Drops}$$
- **Live Integration:** $105 = 105 + 0$ (100.00% delivery)
- **1,000-Event Stress Benchmark:** $1,025 = 1,025 + 0$ (100.00% delivery)
- **Controlled Saturation (256 KiB, 4s pause):** $1,102 = 751 + 351$ (100.00% delivery of submitted records, 31.85% dropped at kernel buffer boundary)
- **Execution Path Suite:** $89 = 89 + 0$ (100.00% delivery)
- **Overhead Benchmark:** $2,036 = 2,036 + 0$ (100.00% delivery)
- **No Clamping / Discrepancy Auditing:** `scripts/saturation_test.sh` and `scripts/stress_test.sh` were audited to eliminate any `min(100.0, ...)` clamping. If decoded events exceed submitted events, the test harness immediately aborts with an invariant violation.

### 3.2 Process Identity Decoupling
- **Architecture:** Separated immutable identity `ProcessInstanceKey{TGID, StartTimeNS}` from mutable execution context (`CgroupID`).
- **Parent Cgroup Resolution:** Resolved in-kernel via BPF CO-RE:
  $$\text{parent\_cgroup\_id} = \text{BPF\_CORE\_READ}(\text{parent\_leader}, \text{cgroups}, \text{dfl\_cgrp}, \text{kn}, \text{id})$$
  Ensures that when host processes (`containerd-shim`) launch container init processes, the child's `ParentKey` references the parent's actual host cgroup rather than falsely assuming container locality.
- **Cgroup Migration:** Verified by moving process `112264` across `/sys/fs/cgroup/cg_mig_test_grp1` and `grp2`. The lineage tracker unified both executions under a single node, preserved historical cgroups in `node.CgroupHistory`, and flagged `cgroup_migrated: true`.

### 3.3 Setuid Validation & Effective-UID Transition
- **Audit Requirement:** Validate setuid execution from an unprivileged context demonstrating a genuine effective-UID transition.
- **Implementation:** Created harmless test binary `bin/cg_setuid_test` (`chown root:root; chmod 4755`). Executed directly from unprivileged user `ram` (UID 1000).
- **Observed Telemetry:**
  - Real UID (`uid`): `1000`
  - Effective UID (`euid`): `0` (root)
  - Event Flag: `CG_FLAG_SETUID_EXEC` (bit 9)
  - Outcome: **PASS** (Genuine unprivileged to privileged EUID transition verified).

### 3.4 Detection Rule Precision & Scope Refinement (CG-RULE-003)
- **Rule CG-RULE-003 Audit:** The rule was audited to ensure accurate scientific claims. Because the probe checks binary path execution (`/bin/sh`, `/bin/bash`, etc.) and does not inspect terminal ptys or `-i` flags, the rule was refined from "Interactive Shell" to **"Shell Binary Executed Inside Container"** (`ContainerShellRule`), with an explicit note that terminal interactivity is not evaluated in the 50% milestone.
- **Evaluation Corpora (Datasets 1 and 2):**
  - **Dataset 2 (Milestone Rerun, 132 events at `b8f70f5`):**
    - Benign Developer Workloads (120 events): Git init/add/commit/diff/log/status, GCC compilation toolchain, container queries.
    - Attack Simulations (12 events): Breakout utilities (`nsenter`, `unshare`, `chroot`, `modprobe`), writable directory executions (`/tmp`, `/dev/shm`, `/var/tmp`), container shell executions (`/bin/sh`).
    - Results:
      - `CG-RULE-001`: TP=4, FP=0, TN=128, FN=0 (Precision=100%, Recall=100%, FPR=0.00%)
      - `CG-RULE-002`: TP=3, FP=0, TN=129, FN=0 (Precision=100%, Recall=100%, FPR=0.00%)
      - `CG-RULE-003`: TP=5, FP=0, TN=127, FN=0 (Precision=100%, Recall=100%, FPR=0.00%)
  - **Dataset 1 (Initial Evaluation, 133 events at `7c56b1e`):**
    - Included the 132 scripted operations plus 1 ambient host IDE invocation (`/usr/bin/git`, `TGID: 16615`, `ParentTGID: 1016`, comm `language_server`, cgroup `22`) captured during shutdown drain.
    - Ground truth: Benign background IDE activity. ContainerGuard attribution: Left as `UNRESOLVED` (cgroup 22 unmapped).
    - Result: No alert emitted; scored as +1 True Negative across all rules (TN: 129, 130, 128; Precision=100%, FPR=0.00%).
  - Note on Claims: Results represent empirical metrics on the evaluation corpus; universal zero false-positive claims across all production environments are not made.

### 3.5 Performance Methodology & Latency Characterization
- **Methodology Audit:** The overhead benchmark was audited to prevent conflating wall-clock time difference with pure kernel syscall latency.
- **Workload:** 2,000 rapid process executions across 4 worker streams (500 each).
- **Measurements:**
  - Baseline (Unmonitored) Time: 0.4267s (4,687.34 ev/s)
  - Monitored (ContainerGuard) Time: 0.4520s (4,424.29 ev/s)
  - Execution Time Overhead: **+5.95%**
  - Throughput Impact: **-5.61%**
  - Amortized Workload Wall-Clock Delta / Event: **12.68 microseconds** from raw unrounded timestamps ($0.02536\text{ s} / 2000$), or **12.65 microseconds** when evaluated with 4-decimal rounded values ($0.0253\text{ s} / 2000$). Note: Includes process fork, execution, and exit; does not isolate pure kernel syscall entry-to-exit latency.
  - Daemon CPU Utilization: **0.75%** (Peak: 0.90%)
  - Daemon Resident Memory (RSS): **6.04 MiB**

---

## 4. Regression & Verification Command Log

| Verification Step | Command Executed | Outcome |
| :--- | :--- | :--- |
| **Go Format & Vet** | `gofmt -w . && go vet ./...` | Code clean, 0 warnings |
| **Race-Enabled Unit Tests**| `go test -race -v ./...` | **PASS** (All packages, 0 race conditions) |
| **eBPF Compilation** | `clang -g -O2 -target bpf ... -c bpf/execve_events.c` | **PASS** (Zero warnings, clean ELF) |
| **Daemon Compilation** | `go build -o bin/containerguard ./cmd/containerguard` | **PASS** (Clean binary generated) |
| **Live Integration Test** | `sudo ./scripts/live_integration_test.sh` | **PASS** (105 events, 3 alerts, 0 drops) |
| **Stress Benchmark** | `sudo ./scripts/stress_test.sh 1000` | **PASS** (1,025 events, 100% delivery) |
| **Saturation & Loss Test** | `sudo ./scripts/saturation_test.sh sat_acceptance_check 256 4 4 250`| **PASS** (351 drops accounted, 100% delivery of submits) |
| **Execution Path Suite** | `sudo ./scripts/execution_path_test.sh` | **PASS** (All 12 paths & setuid transition verified) |
| **Detection Benchmark** | `sudo ./scripts/detection_benchmark.sh` | **PASS** (100% precision & recall, 0 false positives) |
| **Overhead Benchmark** | `sudo ./scripts/overhead_benchmark.sh` | **PASS** (+5.95% overhead, 6.04 MiB RSS) |

---

## 5. Known Limitations of the 50% Milestone Implementation

1. **Interactivity Detection Boundary (CG-RULE-003):** The detection rule intercepts shell binary execution (`/bin/sh`, `/bin/bash`, etc.) inside containers. It does not inspect pseudo-terminal devices (pty/tty) or process command-line flags (`-i`), meaning non-interactive container script wrappers invoking `/bin/sh` trigger this rule.
2. **Execveat Argument Inspection:** The probe captures `dfd`, `filename`, and `flags` (including `AT_EMPTY_PATH`). Full path resolution of file descriptors pointing to deleted files or proc self descriptors is deferred to future work.
3. **Tracepoint vs LSM Hooking:** Tracepoints observe syscall execution attempts and completions. They operate post-invocation and cannot block or prevent unauthorized executions in real time.
4. **Single-Node Focus:** ContainerGuard 50% milestone operates strictly on local Linux nodes/WSL2 and does not provide multi-host distributed aggregation.

---

## 6. Raw Evidence File Index

All raw empirical evidence and metric dumps generated during this milestone evaluation are preserved in:
- `docs/evidence/phase_f/`: Phase F initial live integration logs.
- `docs/evidence/phase_h/`: Phase H multi-tier stress test logs (`stress_1000`, `stress_5000`, `stress_10000`, `stress_25000`).
- `docs/evidence/phase_h2/`: Phase H.2 saturation suite evidence (`suite1_capacity_8stream/`, `suite2_backpressure/`, `original_unreconciled/`).
- `docs/evidence/phase_i/`: Phase I adversarial telemetry, execution paths, detection validation, and overhead benchmark reports:
  - `execution_path_report.json` & `exec_paths_events.jsonl`
  - `detection_validation_report.json` & `detection_alerts.jsonl`
  - `overhead_benchmark_report.json` & `overhead_resource_samples.csv`

---

## 7. Mandatory Development Stop

In strict adherence to the project completion gate directives:
1. **Scope Frozen:** All 16 components of the first 50% milestone are verified, tested, and documented.
2. **No Phase II Development:** Autonomous implementation has terminated.
3. **Standby State:** Antigravity is now halted in a clean, reproducible state, awaiting explicit user instructions before undertaking any further research or engineering tasks.
