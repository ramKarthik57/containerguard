# ContainerGuard: Empirical Stress Testing and Telemetry Integrity Evaluation

## 1. Experimental Methodology and Test Design

The primary objective of Phase H stress testing is to empirically evaluate the telemetry integrity, throughput limits, and detection reliability of ContainerGuard under high event volume and concurrent multi-stream workload pressure.

The central research hypothesis is:
> *A kernel-level eBPF intrusion detection monitor with BPF ring buffer queuing and explicit loss accounting can maintain lossless event ingestion, accurate container attribution, and deterministic threat detection under high concurrency, while transparently bounding and reporting any event loss.*

### 1.1 Test Environment and Kernel Specification
* **Host Platform:** Ubuntu 26.04.1 LTS on x86_64 under WSL2 (Windows 11).
* **Linux Kernel:** `6.18.33.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Fri Jun 5 01:12:21 UTC 2026`.
* **eBPF Subsystem:** BPF CO-RE with `vmlinux.h`, 16 MB ring buffer (`bpf_ringbuf`), atomic monotonic sequence allocator.
* **Container Runtime:** Docker Engine with `cgroupfs v2` unified hierarchy under `systemd` scopes.
* **Instrumentation Hook:** Kernel tracepoint `sys_enter_execve`.

### 1.2 Multi-Stream Workload Generation Model
The stress harness (`scripts/stress_test.sh`) dispatches concurrent process execution bursts partitioned across four isolated parallel execution streams:
1. **Stream 1 (Container A):** Dedicated parallel loop inside persistent research container `cg-test-a`.
2. **Stream 2 (Container B):** Dedicated parallel loop inside persistent research container `cg-test-b-event-test`.
3. **Stream 3 (Ephemeral Stress Container):** Dedicated parallel loop inside temporary container `cg-stress-worker`.
4. **Stream 4 (Host Pipeline Stress):** Parallel loop on the host executing rapid commands to exercise host inode resolution, attribution transitions, and pending buffer limits.
5. **Adversarial In-Band Injection:** A deliberate security violation (execution from writable directory `/tmp/exploit_sim.sh`) is injected into Stream 2 during peak load to test whether intrusion alerts are preserved without degradation during traffic surges.

---

## 2. Telemetry Accounting and Integrity Metrics

The evaluation tracks four independent levels of accounting:
1. **Kernel Reservation Layer:** `telemetry_counters[CG_METRIC_RB_RESERVE_DROPS]` measures whether ring buffer memory was exhausted before submission.
2. **Kernel Submission Layer:** `telemetry_counters[CG_METRIC_RB_SUBMITTED]` records verified ring buffer commits.
3. **Transport/Sequence Layer:** Monotonic sequence numbers and `SequenceTracker` watermark window track reader loss or dropped frames.
4. **Userspace Pipeline Layer:** Ingestion buffer gauges, attribution resolution status, and rule engine alert queues.

$$\text{Delivery Rate} = \frac{\text{Userspace Records Received}}{\text{Kernel Hook Invocations}} \times 100\%$$

$$\text{Throughput} = \frac{\text{Observed Hook Calls}}{\text{Elapsed Execution Time (s)}}$$

$$\text{Kernel Drop Rate} = \frac{\text{Ring Buffer Reserve Drops}}{\text{Kernel Hook Invocations}} \times 100\%$$

$$\text{Attribution Recall} = \frac{\text{Container Events Resolved}}{\text{Actual Container Workload Executions}} \times 100\%$$

---

## 3. Empirical Test Matrix Across Load Tiers

| Metric / Parameter | Tier 1 (1,000 Target) | Tier 2 (5,000 Target) | Tier 3 (10,000 Target) | Tier 4 (25,000 Target) |
|---|---|---|---|---|
| **Target Event Workload** | 1,000 events | 5,000 events | 10,000 events | 25,000 events |
| **Worker Concurrency Streams** | 4 parallel streams | 4 parallel streams | 4 parallel streams | 4 parallel streams |
| **Worker Sub-Bursts per Stream** | 250 executions | 1,250 executions | 2,500 executions | 6,250 executions |
| **Total Workload Execution Time** | **0.798 seconds** | *Pending* | *Pending* | *Pending* |
| **Observed Kernel Hooks** | **1,040** | *Pending* | *Pending* | *Pending* |
| **Ring Buffer Submissions** | **1,040** | *Pending* | *Pending* | *Pending* |
| **Ring Buffer Reservation Drops** | **0 (0.00%)** | *Pending* | *Pending* | *Pending* |
| **Cgroup Map Failures** | **0** | *Pending* | *Pending* | *Pending* |
| **Userspace Records Received** | **1,040** | *Pending* | *Pending* | *Pending* |
| **Userspace Records Decoded** | **1,040** | *Pending* | *Pending* | *Pending* |
| **Decode Failures** | **0** | *Pending* | *Pending* | *Pending* |
| **Sequence Gaps Detected** | **0** | *Pending* | *Pending* | *Pending* |
| **Transient Reordered Events** | **0** | *Pending* | *Pending* | *Pending* |
| **Events Attributed to Containers** | **762** | *Pending* | *Pending* | *Pending* |
| **Events Evaluated as Host/Unresolved** | **278** | *Pending* | *Pending* | *Pending* |
| **False-Positive Host Attributions** | **0** | *Pending* | *Pending* | *Pending* |
| **Current Pending Queue Depth (Exit)**| **0** | *Pending* | *Pending* | *Pending* |
| **Peak Pending Queue Depth** | **277** | *Pending* | *Pending* | *Pending* |
| **Userspace Ingest Overflows** | **0** | *Pending* | *Pending* | *Pending* |
| **Measured Event Throughput** | **1,302.6 events/sec** | *Pending* | *Pending* | *Pending* |
| **Telemetry Delivery Rate** | **100.00%** | *Pending* | *Pending* | *Pending* |
| **Critical Alert Retention** | **100% (Alert 1028 preserved)**| *Pending* | *Pending* | *Pending* |

---

## 4. In-Depth Analysis of Tier 1 (1,000 Events)

### 4.1 Telemetry Delivery and Throughput Performance
* **Throughput:** Under 4 concurrent worker processes, the eBPF tracepoint, BPF ring buffer, and userspace decoding pipeline processed **1,040 events in 0.798 seconds**, representing a sustained throughput of **1,302.6 events per second**.
* **Lossless Transport:** Zero ring buffer drops (`CG_METRIC_RB_RESERVE_DROPS = 0`) and zero sequence gaps (`sequence_gaps_detected = 0`). Every single kernel hook invocation was received, validated, unpacked, and processed in userspace (100.00% delivery rate).

### 4.2 Attribution State Machine Under Concurrency
* **Container Attributions (762 events):**
  - All executions within `cg-test-a`, `cg-test-b-event-test`, and `cg-stress-worker` were correctly mapped to their respective container IDs via the BPF cgroup hash map and userspace container cache.
  - No container execution was erroneously tagged as host or lost.
* **Host / Non-Container Executions (278 events):**
  - Host process executions (from the concurrent host stream and shell loops) were placed into the pending attribution buffer, evaluated against the Docker container inventory and root cgroup, and classified as `UNRESOLVED` non-container events.
  - Zero false-positive container attributions occurred.
* **Pending Buffer Dynamics:**
  - `attribution_pending_transitions`: 278 cumulative transitions into the buffer.
  - `peak_pending_queue_depth`: 277 concurrent pending items.
  - `current_pending_queue_depth`: Drained cleanly to 0 upon daemon shutdown.
  - The peak queue depth (277) was safely within the bounded ring capacity of 4,096 entries, confirming that the queue bounds are well-dimensioned for high-frequency bursts.

### 4.3 Adversarial Alert Preservation Under Load
A critical vulnerability in many logging and monitoring systems is alert starvation or event drop during traffic spikes (denial-of-telemetry).
* At sequence number **1028** (mid-burst during parallel load), an adversarial script `/tmp/exploit_sim.sh` was executed inside container `cg-test-b-event-test`.
* ContainerGuard successfully intercepted the event, evaluated it against the deterministic rule engine, and generated:
  ```json
  {
    "id": "ALERT-1028-CG-RULE-002",
    "rule_id": "CG-RULE-002",
    "title": "Execution From Writable Directory",
    "description": "Executable launched from writable memory/temp mount '/tmp/exploit_sim.sh'",
    "severity": "HIGH",
    "timestamp": "2026-11-08T04:40:52.873736874Z",
    "event": {
      "seq_num": 1028,
      "cgroup_id": 5960,
      "tgid": 22629,
      "parent_tgid": 21642,
      "filename": "/tmp/exploit_sim.sh",
      "attribution_state": "RESOLVED",
      "container_name": "cg-test-b-event-test"
    }
  }
  ```
* Lineage reconstruction correctly linked this child execution (`TGID 22629`, `StartTimeNS 14929002760043`) back to the interactive parent shell (`TGID 21642`, `StartTimeNS 14928399612031`).
* **Conclusion:** Deterministic threat detection and complete process lineage are fully preserved under concurrent load.

---

## 5. Next Stress Tiers Protocol

To execute the remaining tiers:
```bash
# Tier 2: 5,000 events
sudo ./scripts/stress_test.sh 5000

# Tier 3: 10,000 events
sudo ./scripts/stress_test.sh 10000

# Tier 4: 25,000 events (Saturation test)
sudo ./scripts/stress_test.sh 25000
```
Each run will produce detailed accounting reports in `/tmp/cg_stress_<count>/report.json`, verifying the telemetry boundary limits and identifying the saturation point of the 16 MB ring buffer.
