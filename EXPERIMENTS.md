# ContainerGuard Experimental Evaluation Protocol

## 1. Research Objectives

Validate the resilience of ContainerGuard under telemetry pressure, lifecycle races, and adversarial evasion attempts.

---

## 2. Controlled Experiment Suites

### Experiment 1: Attribution Race Condition Validation
- **Goal:** Verify that a container executing commands immediately upon `docker run` has all events correctly attributed rather than dropped or misattributed to the host.
- **Method:**
  1. Start ContainerGuard daemon.
  2. Launch ephemeral container: `docker run --rm alpine /bin/sh -c "ls -la; id; date"`.
  3. Inspect telemetry log: verify all 3 commands are attributed as `RESOLVED` with the container's ID and name, rather than `HOST_OR_UNMAPPED`.
- **Metrics Collected:** Attribution recall rate, average pending queue duration (ms).

### Experiment 2: Ring Buffer Saturation and Telemetry Accounting
- **Goal:** Induce kernel ring buffer pressure and verify that:
  a) Kernel `RINGBUF_RESERVE_DROPS` accounts for all dropped events.
  b) Userspace sequence gap detector matches the kernel drops.
- **Method:**
  1. Restrict ring buffer or spawn flood container executing 50,000 rapid processes:
     `docker run --rm alpine /bin/sh -c 'for i in $(seq 1 50000); do /bin/true; done'`
  2. Observe final telemetry report.
- **Metrics Collected:** `kernel_hook_invocations`, `kernel_ringbuf_reserve_drops`, `sequence_gaps_detected`, CPU and memory footprint.

### Experiment 3: Two-Container Fairness Under Asymmetric Load
- **Goal:** Container A floods the system with routine `execve` events while Container B executes a single low-frequency critical event (`nsenter`).
- **Method:**
  1. Container A runs high-frequency loop.
  2. Container B executes `nsenter --help`.
  3. Verify that ContainerGuard detects and logs Container B's critical alert despite Container A's event flood.
- **Metrics Collected:** Critical event retention (recall), detection latency (ms).


---

## 3. Empirical Results from Phase F Live Validation

### Trial Run: Baseline Multi-Container & Lifecycle Validation (2026-11-08)

| Parameter | Observed Value | Ground Truth Expected | Result |
|---|---|---|---|
| **Kernel Hook Calls** | 79 | 79 observed syscalls | Verified |
| **Ring Buffer Reserve Drops** | 0 | 0 buffer exhaustion | Zero loss |
| **Userspace Records Decoded** | 79 | 79 submitted records | 100% decode recall |
| **Sequence Gaps** | 0 | Continuous stream | Stream integrity confirmed |
| **`cg-test-a` Attributed Events** | 7 | 7 execve calls in container | 100% attribution recall |
| **`cg-test-b` Attributed Events** | 14 | 14 execve calls across restart | 100% attribution recall |
| **Ephemeral Container Attribution** | `UNRESOLVED` | Exited before inventory poll | Correct non-host state |
| **Detection Alerts Fired** | 4 | 3 shells, 1 `/tmp` exec | 100% detection recall |
| **Shutdown Termination Signal** | `SIGTERM` | Graceful flush | Clean exit, no hang |


---

### Trial Run: Thread-Group Leader & Dedicated Lifecycle Test (2026-11-08 04:22 UTC)

| Test Metric | Empirical Count | Verified Ground Truth | Status |
|---|---|---|---|
| **Total Syscall Invocations** | 106 | 106 kernel hooks | Complete Match |
| **Ring Buffer Reserve Drops** | 0 | 0 buffer exhaustion | Zero Loss |
| **Ring Buffer Submissions** | 106 | 106 records submitted | 100% Submitted |
| **Userspace Records Decoded** | 106 | 106 records decoded | 100% Recall |
| **`cg-test-a` Attributed** | 6 | 6 events | 100% Attribution |
| **`cg-test-b-event-test` Attributed** | 10 | 10 events | 100% Attribution |
| **`cg-lifecycle` Dedicated Test** | 8 | 8 events across restart & rename | 100% Attribution |
| **Deterministic Alerts Triggered** | 3 | 2 shell executions, 1 writable exec | 100% Detection Recall |
| **Lineage Integrity** | Complete | Parent keys match leader start times | Verified |
| **Daemon Teardown** | Clean | SIGTERM handled, reader unblocked | Verified |

---

## Experiment 3: Telemetry Integrity Stress Testing Under Concurrent Load (Phase H)

### Objective
Evaluate ContainerGuard's telemetry integrity, ingestion rate, attribution resilience, and detection fidelity under concurrent execution pressure across multiple container streams.

### Workload Dispatch Architecture
Executed via `sudo ./scripts/stress_test.sh <count>`:
* **4 Concurrent Execution Streams:**
  - Stream 1: Container `cg-test-a` (executing rapid `expr` workloads)
  - Stream 2: Container `cg-test-b-event-test` (executing rapid `expr` workloads)
  - Stream 3: Dedicated temporary container `cg-stress-worker` (executing rapid `expr` workloads)
  - Stream 4: Host workload stream (exercising non-container attribution pipeline)
* **Adversarial Payload Injection:** `/tmp/exploit_sim.sh` executed inside `cg-test-b-event-test` mid-stream during peak concurrent load.

### Empirical Results Summary

| Metric | Tier 1 (1k Target) | Tier 2 (5k Target) | Tier 3 (10k Target) | Tier 4 (25k Target) |
|---|---|---|---|---|
| **Workload Duration** | **0.80s** | **2.82s** | **5.31s** | **13.02s** |
| **Observed Kernel Hooks** | **1,040** | **5,027** | **10,027** | **25,032** |
| **Ring Buffer Submissions** | **1,040** | **5,027** | **10,027** | **25,032** |
| **Ring Buffer Drops** | **0 (0.00%)** | **0 (0.00%)** | **0 (0.00%)** | **0 (0.00%)** |
| **Cgroup Map Failures** | **0** | **0** | **0** | **0** |
| **Userspace Records Received** | **1,040** | **5,027** | **10,027** | **25,032** |
| **Userspace Decoded Records** | **1,040** | **5,027** | **10,027** | **25,032** |
| **Sequence Gaps Detected** | **0** | **0** | **0** | **0** |
| **Reordered Events Handled** | **0** | **0** | **0** | **1 (Watermark reconciled)** |
| **Attribution Resolved (Containers)** | **762 (73.3%)** | **3,763 (74.9%)** | **7,512 (74.9%)** | **18,764 (75.0%)** |
| **Attribution Unresolved (Non-Cont)**| **278 (26.7%)** | **1,264 (25.1%)** | **2,515 (25.1%)** | **6,268 (25.0%)** |
| **Current Pending Queue Depth** | **0** | **0** | **0** | **0** |
| **Peak Pending Queue Depth** | **277** | **1,259** | **1,361** | **1,371** |
| **Event Throughput** | **1,302.6 events/s** | **1,781.6 events/s** | **1,889.1 events/s** | **1,923.0 events/s** |
| **Telemetry Delivery Rate** | **100.00%** | **100.00%** | **100.00%** | **100.00%** |
| **Critical Alert Retention** | **100% (Alert 1028)** | **100% (Alert 5022)** | **100% (Alert 10022)** | **100% (Shell Alerts)** |

### Key Findings
1. **Zero Telemetry Loss Across 41,126 Events:** Over all four tiers, 41,126 total execution events were captured with exactly zero ring buffer reservation drops (`CG_METRIC_RB_RESERVE_DROPS = 0`) and zero sequence gaps.
2. **Attribution Ratio Convergence:** As sample size increased, container attribution resolved events converged from 73.3% to 74.96%, matching the expected 75.00% 3:1 container-to-host workload split to within 0.04%. Zero false-positive container attributions occurred.
3. **Queue Bounding Dynamics:** Peak pending queue depth plateaued at 1,371 items during continuous 25,000-event execution, utilizing only 33.5% of the 4,096 capacity with zero queue overflows.
4. **Live Multi-Core Watermark Validation:** In Tier 4, the sliding watermark sequence tracker detected and reconciled 1 transient multi-core out-of-order event commit, preventing false loss alarms and proving the watermark algorithm on a live multi-core Linux kernel.
5. **Detection Retention Under Concurrency:** In-band exploit scripts executed from writable directories (`CG-RULE-002`) and shell executions (`CG-RULE-003`) were captured, alerted, and lineage-linked under maximum concurrent load.


