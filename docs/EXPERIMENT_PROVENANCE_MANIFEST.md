# ContainerGuard: Experiment Provenance & Cryptographic Traceability Manifest

## 1. Provenance Integrity Guarantee

ContainerGuard is a cybersecurity research project with strict empirical reproducibility requirements. Every benchmark result, telemetry dataset, alert trace, and overhead calculation published in the repository is tied to an immutable Git commit, cryptographic checksums, and preserved raw event archives.

> [!IMPORTANT]
> **Frozen Milestone Policy:** The core implementation at commit `b8f70f5` represents the official **ContainerGuard 50% Verified Milestone**. Subsequent commits are strictly constrained to documentation, non-destructive test-harness verification enhancements, build maintenance, and research reporting.
>
> **System-Under-Test vs. Test-Harness Revisions:** To maintain strict research auditability:
> - **System-Under-Test (SUT):** Refers to the daemon source code, eBPF C program, and compiled release binaries (`bin/containerguard`, `bpf/execve_events.o`) frozen at milestone commit `b8f70f5`.
> - **Test-Harness:** Refers to the benchmark orchestration scripts (`scripts/*.sh`) and test runners (`cmd/test_exec_paths/`), which have evolved across PR #5, PR #6, and PR #7 to provide strict process-specific (PID-to-TGID) assertion validation, ephemeral runner sandboxing, container auto-initialization, and collision-resistant evidence directory isolation.

---

## 2. Official Release Checkpoints & Binary Integrity

The official compiled binaries corresponding to the **ContainerGuard 50% Verified Milestone** (`b8f70f5`) are tracked in the repository with the following cryptographic digests:

| Component | Repository Path | Cryptographic SHA-256 Digest |
| :--- | :--- | :--- |
| **Go Control-Plane Daemon** | `bin/containerguard` | `cfee0d9675b653fdd7cda2629454a4839b1fd59ede0ba43f8bcd7ce7bebc93d0` |
| **Compiled eBPF Kernel ELF**| `bpf/execve_events.o` | `6ae519a012694f11c9ab514c1b13cafb4b8551fb8deadaf10dee817862717ef3` |
| **Test Execution Harness**  | `bin/test_exec_paths` | `37890b6bbc638c6066609afbd2cc98cfcb3ca70cd996385a44e4728f1459a32f` |
| **Setuid Test Executable**   | `bin/cg_setuid_test`  | `b11b8709bfa3e4038ecfe7705500c9733be248e168af7991ae6e170c01596a95` |

*Verification Command:*
```bash
sha256sum bin/containerguard bpf/execve_events.o bin/test_exec_paths bin/cg_setuid_test
```

---

## 3. Comprehensive Experiment Manifest Matrix

| Experiment ID | Focus Area | System-Under-Test Revision | Test-Harness Revision | Script & Invocations | Workload Parameters | Preserved Raw Evidence Archive | Authoritative Metric |
| :--- | :--- | :---: | :---: | :--- | :--- | :--- | :--- |
| **EXP-1** | Baseline Container Attribution & Inode Discovery | `b8f70f5` | `b8f70f5` | `sudo ./scripts/live_integration_test.sh` | 2 persistent containers (`cg-test-a`, `cg-test-b-event-test`), 1 ephemeral container, 1 host stream | [`evidence/phase_f/`](evidence/phase_f/) | 105 events captured, 0 kernel drops, 100.0% delivery, 3 alerts emitted |
| **EXP-2** | Concurrent Workload Scaling (Phase H) | `b8f70f5` | `b8f70f5` | `sudo ./scripts/stress_test.sh 1000`<br/>`sudo ./scripts/stress_test.sh 5000`<br/>`sudo ./scripts/stress_test.sh 10000`<br/>`sudo ./scripts/stress_test.sh 25000` | 4 concurrent execution streams (2 persistent containers, 1 ephemeral, 1 host) with exploit injection mid-stream | [`evidence/phase_h/stress_1000/`](evidence/phase_h/stress_1000/)<br/>[`evidence/phase_h/stress_5000/`](evidence/phase_h/stress_5000/)<br/>[`evidence/phase_h/stress_10000/`](evidence/phase_h/stress_10000/)<br/>[`evidence/phase_h/stress_25000/`](evidence/phase_h/stress_25000/) | 1,040 to 25,032 events; 0 kernel drops; 0 sequence gaps; 100.0% delivery up to 1,923.0 hooks/s |
| **EXP-3** | Controlled Buffer Saturation & Reader Backpressure (Phase H.2) | `96f36ce` | `96f36ce` | `sudo ./scripts/saturation_test.sh sat_16mb_8stream 16384 0 8 250`<br/>`sudo ./scripts/saturation_test.sh sat_bp_256kb 256 4 4 500`<br/>`sudo ./scripts/saturation_test.sh sat_bp_64kb 64 4 4 500` | 2,000 target events under 4.0-second induced userspace reader backpressure across buffer sizes (64KB, 256KB, 16MB) | [`evidence/phase_h2/suite1_capacity_8stream/`](evidence/phase_h2/suite1_capacity_8stream/)<br/>[`evidence/phase_h2/suite2_backpressure/`](evidence/phase_h2/suite2_backpressure/)<br/>[`evidence/phase_h2/original_unreconciled/`](evidence/phase_h2/original_unreconciled/) | Exact conservation: $\text{Hooks} = \text{Submissions} + \text{Drops}$. 64KB held 190 events during freeze; 256KB held 762 events (344B wire schema). Zero sequence gaps. |
| **EXP-4 (Baseline Archive)** | Execution-Path Semantics & Credential Transitions (Phase I Baseline) | `b8f70f5` | `b8f70f5` (Original Release Harness) | `./scripts/execution_path_test.sh` *(unprivileged caller)* | 14 execution conditions: direct syscall, relative `execveat`, anonymous `memfd`, static ELF, symlinks, setuid EUID 0 transition, failed `ENOENT`/`EACCES`, and live cgroup migration | **Preserved Baseline Archive:**<br/>[`evidence/phase_i/execution_path_report.json`](evidence/phase_i/execution_path_report.json)<br/>[`evidence/phase_i/exec_paths_events.jsonl`](evidence/phase_i/exec_paths_events.jsonl) | 89 total events captured at 2026-11-08T07:33:55Z; 87 committed (`sched_process_exec`); 2 failed (`sys_exit_execve`); 0 drops; setuid `CG_FLAG_SETUID_EXEC` verified; cgroup migration tracked |
| **EXP-4-R (Reproduction Protocol)** | Process-Correlated Execution-Path Telemetry & Accounting | `b8f70f5` (Release SUT) | Current (`PR #16`, commit `dad4a08` base) | `./scripts/execution_path_test.sh` *(unprivileged caller)* | 14 execution pathways with PID-to-TGID tracking serialized in `test_pids.json`, ephemeral setuid runner, and complete telemetry loss accounting | **Live Reproduction Run Output:**<br/>`evidence/phase_i/runs/<run_id>/`<br/>*(Outputs to isolated timestamped directory)* | *Acceptance Criteria Enforced by Harness:*<br/>14/14 execution path assertions strictly enforced; process-specific correlation (all 13 test PIDs in live reproduction; 11/14 TGID-correlated: 10 reconstructed execution-path TGIDs and the historical cgroup-migration TGID 984, 1/14 container-name matched, and 2/14 event-signature based in historical archive evaluation); zero kernel drops (`drops == 0`); zero userspace loss (`decoded == submitted == events_processed`); zero decode failures; zero queue overflows; zero sequence gaps |
| **EXP-5A**| Detection Validation & False-Positive Evaluation (Phase I) | `7c56b1e` (Dataset 1)<br/>`b8f70f5` (Dataset 2) | `b8f70f5` | `sudo ./scripts/detection_benchmark.sh` | Interleaved corpus: 120 benign operations (Git queries, multi-stage GCC compilation) vs 12 synthetic attack simulations | [`evidence/phase_i/detection_validation_report.json`](evidence/phase_i/detection_validation_report.json)<br/>[`evidence/phase_i/detection_alerts.jsonl`](evidence/phase_i/detection_alerts.jsonl) | Dataset 1 (133 events): TP=12, TN=387, FP=0, FN=0.<br/>Dataset 2 (132 events): TP=12, TN=384, FP=0, FN=0.<br/>100% Precision, 100% Recall on labelled suite. |
| **EXP-5B**| Monitoring Runtime Overhead & Resource Footprint (Phase I) | `7c56b1e` (Trial 1)<br/>`b8f70f5` (Trial 2) | `b8f70f5` | `sudo ./scripts/overhead_benchmark.sh` | 2,000 rapid process executions across 4 worker streams with pre-test cache drops (`drop_caches`), comparing unmonitored vs ContainerGuard monitored | [`evidence/phase_i/overhead_benchmark_report.json`](evidence/phase_i/overhead_benchmark_report.json)<br/>[`evidence/phase_i/overhead_resource_samples.csv`](evidence/phase_i/overhead_resource_samples.csv) | Trial 1 (+3.46% overhead, 7.77 µs delta/lifecycle); Trial 2 (+5.95% overhead, 12.68 µs delta/lifecycle); Descriptive mean: 4.71%; Peak RSS: 6.04 MiB |

---

## 4. Step-by-Step Independent Reproduction Protocol

To independently execute and verify ContainerGuard:

### Step 0: Research Environment Prerequisites & Container Preparation
The experiment suites evaluate both host and container workloads. Ensure Docker is running and initialize the standard research containers (`cg-test-a` and `cg-test-b-event-test`):
```bash
# 1. Verify Docker daemon is active
sudo systemctl is-active docker || sudo service docker start

# 2. Ensure research baseline containers exist and are active
for c in cg-test-a cg-test-b-event-test; do
    if ! sudo docker ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
        sudo docker run -d --name "${c}" busybox:latest sleep 3600
    fi
    sudo docker start "${c}" >/dev/null 2>&1 || true
done
```
*(Note: Test runners such as `scripts/execution_path_test.sh` and `scripts/live_integration_test.sh` automatically verify and initialize these containers if absent).*

### Step 1: Clean Build Verification
```bash
# Verify no dirty state in Git
git status

# Run the automated build script (compiles into build/ to preserve tracked release binaries)
./scripts/build.sh

# Confirm newly compiled build artifacts in build/
sha256sum build/bin/containerguard build/bpf/execve_events.o

# Confirm tracked official release binary digests remain intact in bin/ and bpf/
sha256sum bin/containerguard bpf/execve_events.o
```

### Step 2: Unprivileged Test Verification
```bash
# Execute unit tests with Go race detector
go test -v -race -count=1 ./internal/...
```

### Step 3: Privileged eBPF Telemetry Reproduction (Requires Root / Interactive Sudo)
```bash
# 1. Execution-Path Semantics Suite (EXP-4)
# Option A: Evaluate historical baseline archive in archive mode (non-destructive, no root needed):
./scripts/execution_path_test.sh --archive-eval

# Option B: Live reproduction run (requires interactive root privileges for daemon attachment):
# Note: Execute directly as an unprivileged user (not with sudo). The test harness
# invokes sudo internally for daemon attachment, compiles an ephemeral setuid helper
# inside the run directory, and executes it from caller context to verify the unprivileged
# UID 1000 -> EUID 0 credential transition while preserving tracked release binaries.
./scripts/execution_path_test.sh

# 2. Detection Rule Validation (EXP-5A)
sudo ./scripts/detection_benchmark.sh

# 3. Controlled Ring Buffer Saturation (EXP-3, 256 KiB, 4-second pause)
sudo ./scripts/saturation_test.sh sat_reproduce_256kb 256 4 4 500

# 4. Runtime Overhead Benchmark (EXP-5B)
sudo ./scripts/overhead_benchmark.sh
```

---

## 5. Provenance Notes on Historical Schema Changes

1. **Phase H.2 vs Release Event Schema:**
   - Experiments 1–3 were initially measured using `struct exec_event` containing 336 bytes (wire footprint: 344 bytes including `struct bpf_ringbuf_hdr`).
   - Experiments 4–5 and the frozen release binary (`b8f70f5`) expanded `struct exec_event` to 360 bytes (wire footprint: 368 bytes) to capture parent start time (`parent_start_time_ns`), effective UID (`euid`), and `execveat` directory file descriptors (`dfd`, `at_flags`).
   - Both schemas and their corresponding theoretical buffer capacities are formally preserved in [`docs/SATURATION_EVALUATION.md`](SATURATION_EVALUATION.md).

2. **Ambient IDE Process in Dataset 1:**
   - In Dataset 1 (`7c56b1e`), the 133rd event was forensically verified as `/usr/bin/git` invoked by the VS Code / Antigravity IDE language server (`PPID 1016`, `cgroup 22`).
   - ContainerGuard correctly categorized this unmapped cgroup as `UNRESOLVED` rather than defaulting to the host, resulting in 0 alerts and +1 True Negative per rule.
   - Dataset 2 (`b8f70f5`) reproduced the benchmark in an ambient-free environment, yielding exactly 132 scripted events.

---
