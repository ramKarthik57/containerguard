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
