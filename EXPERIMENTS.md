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

### Empirical Results Summary (Phase H.1 Reconciled)

| Metric | Tier 1 (1k Target) | Tier 2 (5k Target) | Tier 3 (10k Target) | Tier 4 (25k Target) |
|---|---|---|---|---|
| **Workload Duration** | **0.80s** | **2.82s** | **5.31s** | **13.02s** |
| **Target Workload Throughput** | **1,252.5 ev/s** | **1,772.0 ev/s** | **1,884.0 ev/s** | **1,920.5 ev/s** |
| **Observed Kernel Hooks** | **1,040** | **5,027** | **10,027** | **25,032** |
| **Additional Non-Target Hooks** | **40** | **27** | **27** | **32** |
| **Observed Hook Throughput** | **1,302.6 hooks/s** | **1,781.6 hooks/s** | **1,889.1 hooks/s** | **1,923.0 hooks/s** |
| **Ring Buffer Submissions** | **1,040** | **5,027** | **10,027** | **25,032** |
| **Ring Buffer Reserve Drops** | **0 (0.00%)** | **0 (0.00%)** | **0 (0.00%)** | **0 (0.00%)** |
| **Cgroup Map Failures** | **0** | **0** | **0** | **0** |
| **Userspace Records Decoded** | **1,040** | **5,027** | **10,027** | **25,032** |
| **Telemetry Delivery Rate** | **100.00%** | **100.00%** | **100.00%** | **100.00%** |
| **Sequence Gaps Detected** | **0** | **0** | **0** | **0** |
| **Transient Inverted Allocations** | **0** | **0** | **0** | **1 (Reconciled)** |
| **Container Attributed (RESOLVED)** | **762 (100% recall)**| **3,763 (100% recall)**| **7,512 (100% recall)**| **18,764 (100% recall)**|
| **Non-Container (UNRESOLVED)** | **278** | **1,264** | **2,515** | **6,268** |
| **False Container Attributions** | **0 (100% prec.)** | **0 (100% prec.)** | **0 (100% prec.)** | **0 (100% prec.)** |
| **Peak Pending Queue Depth** | **277** | **1,259** | **1,361** | **1,371** |
| **Pending Queue Depth at Exit** | **0** | **0** | **0** | **0** |
| **Userspace Queue Overflows** | **0** | **0** | **0** | **0** |
| **Deterministic Alert Execution** | **4/4 alerts** | **4/4 alerts** | **4/4 alerts** | **3/3 alerts** |

### Key Findings
1. **Decomposition of Additional Hooks:** 100% of the 126 additional hooks across all tiers were identified: 36 container stream orchestration, 8 host stream orchestration, 29 harness CLI/shim, 11 injected security test conditions, 18 ambient WSL2 system, and 24 trailing residual executions.
2. **Throughput Scaling:** Throughput scaled up to 1,923 observed hooks/sec (1,920.5 target events/sec) without ring buffer reservation drops.
3. **Queue Bounding Dynamics:** Userspace attribution queue reached steady-state equilibrium at 1,371 entries (33.5% of 4,096 capacity), with zero queue overflows.
4. **Multi-Core Sequence Allocation:** The Tier 4 reordering was confirmed as an interleaving between kernel ring buffer reservation and atomic sequence allocation across concurrent cores, which was absorbed by the watermark sequence window without false gap alarms.

---

## Experiment 4: Controlled Ring Buffer Saturation Evaluation (Phase H.2)

### Objective
Identify the empirical telemetry loss boundary of the eBPF monitor by evaluating smaller Ring Buffer configurations (64 KiB, 256 KiB, 1 MiB vs 16 MiB baseline) and introducing controlled userspace reader backpressure to observe kernel-side reservation drops, sequence gap detection, and post-saturation recovery.

### Sizing and Theoretical Limits
* Wire footprint per event: 344 bytes (336 struct + 8 header).
* 64 KiB buffer: holds $\approx 190$ unconsumed events before reservation exhaustion.
* 256 KiB buffer: holds $\approx 762$ unconsumed events.
* 1 MiB buffer: holds $\approx 3,048$ unconsumed events.
* 16 MiB baseline: holds $\approx 48,770$ unconsumed events.

### Empirical Results: Suite 1 (8-Stream Concurrency, Active Drain)
* **Configuration:** 8 streams $\times$ 250 executions = 2,000 target events.
* **Findings:**
  - 16 MiB, 1 MiB, 256 KiB, 64 KiB: **0 drops across all sizes** under active drain.
  - Throughput: 2,316 – 2,445 hooks/sec.
  - Collector RSS: dropped from 56.5 MiB (16 MiB buffer) to 25.0 MiB (1 MiB buffer).

### Empirical Results: Suite 2 (Induced 4-Second Userspace Backpressure, Audited)
* **Configuration:** 4 streams $\times$ 500 executions = 2,000 target events during 4.0s reader freeze.
* **Findings:**
  - `sat_bp_16mb`: 2,105 hooks, 2,105 submitted, **0 drops (0.00% loss)**, 2,105 decoded, 100.00% delivery rate, 0 final queue depth. Absorbed entire burst.
  - `sat_bp_256kb`: 2,102 hooks, 801 submitted, **1,301 drops (61.89% loss)**, 801 decoded, 100.00% delivery rate, 0 final queue depth. Held exactly 762 events during pause ($\lfloor 262,144/344 \rfloor = 762$).
  - `sat_bp_64kb`: 2,104 hooks, 231 submitted, **1,873 drops (89.02% loss)**, 231 decoded, 100.00% delivery rate, 0 final queue depth. Held exactly 190 events during pause ($\lfloor 65,536/344 \rfloor = 190$).
  - **Accounting Conservation:** In all cases, $\text{Hooks} = \text{Submissions} + \text{Drops}$ with 100% mathematical precision.
  - **Recovery:** Once reader resumed, all buffered events drained cleanly without process death, data corruption, or stranded queue entries.





