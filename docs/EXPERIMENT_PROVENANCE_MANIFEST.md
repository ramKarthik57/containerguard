# ContainerGuard: Experiment Provenance & Reproducibility Manifest

This manifest documents the exact provenance, environment parameters, software artifacts, and execution commands required to independently evaluate and reproduce ContainerGuard's empirical benchmark findings.

---

## 1. Verified Hardware & Software Execution Environment

All empirical experiments published in this repository were conducted on the following certified environment:

| Environmental Layer | Specification / Version | Verification Mechanism |
| :--- | :--- | :--- |
| **Host Virtualization** | Microsoft Windows Subsystem for Linux (WSL2) | `uname -r` |
| **Linux Kernel** | `Linux 6.18.33.1-microsoft-standard-WSL2` (x86_64) | `uname -a` |
| **Kernel BTF Support** | In-tree BTF enabled (`/sys/kernel/btf/vmlinux`) | `ls -la /sys/kernel/btf/vmlinux` |
| **Cgroup Hierarchy** | Unified cgroup v2 mounted at `/sys/fs/cgroup` | `stat -f -c %T /sys/fs/cgroup` (`cgroup2fs`) |
| **Operating System** | Ubuntu 26.04.1 LTS (Noble Numbat) | `/etc/os-release` |
| **eBPF Compiler** | Clang / LLVM version `21.1.8` | `clang --version` |
| **Go Toolchain** | Go version `1.26.8` (per `go.mod`) | `go version` |
| **Container Engine** | Docker Engine `29.9.3` / containerd `2.4.2` | `docker version` |
| **Architecture** | x86_64 (64-bit multi-core host) | `lscpu` |

---

## 2. Verified Binary Artifacts & Digest Provenance

The official compiled binaries corresponding to the **ContainerGuard 50% Verified Milestone** checkpoint (`b8f70f5`) exhibit the following cryptographic SHA-256 digests:

| Binary Artifact | Relative Path | SHA-256 Digest |
| :--- | :--- | :--- |
| **Go Control-Plane Daemon** | `bin/containerguard` | `cfee0d9675b653fdd7cda2629454a4839b1fd59ede0ba43f8bcd7ce7bebc93d0` |
| **Compiled eBPF Kernel ELF**| `bpf/execve_events.o` | `6ae519a012694f11c9ab514c1b13cafb4b8551fb8deadaf10dee817862717ef3` |
| **Test Execution Harness**  | `bin/test_exec_paths` | `5cbf23bf62d26f633c39665f84d6b5e0dd22a61c7eb16773a4b64fcad0b0dbe4` |
| **Setuid Test Executable**   | `bin/cg_setuid_test`  | Setuid root binary (`chmod 4755`); compiled from `cmd/test_exec_paths/setuid_test.c` |

*Verification Command:*
```bash
sha256sum bin/containerguard bpf/execve_events.o bin/test_exec_paths
```

---

## 3. Comprehensive Experiment Manifest Matrix

| Experiment ID | Focus Area | Source Commit | Script & Invocations | Workload Parameters | Raw Evidence Archive | Authoritative Metric |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| **EXP-1** | Baseline Container Attribution & Inode Discovery | `b8f70f5` | `sudo ./scripts/live_integration_test.sh` | 2 persistent containers (`cg-test-a`, `cg-test-b`), 1 ephemeral container, 1 host stream | [`evidence/phase_f/`](evidence/phase_f/) | 105 events captured, 0 kernel drops, 100.0% delivery, 3 alerts emitted |
| **EXP-2** | Concurrent Workload Scaling (Phase H) | `b8f70f5` | `sudo ./scripts/stress_test.sh 1000`<br/>`sudo ./scripts/stress_test.sh 5000`<br/>`sudo ./scripts/stress_test.sh 10000`<br/>`sudo ./scripts/stress_test.sh 25000` | 4 concurrent execution streams (2 persistent containers, 1 ephemeral, 1 host) with exploit injection mid-stream | [`evidence/phase_h/stress_1000/`](evidence/phase_h/stress_1000/)<br/>[`evidence/phase_h/stress_5000/`](evidence/phase_h/stress_5000/)<br/>[`evidence/phase_h/stress_10000/`](evidence/phase_h/stress_10000/)<br/>[`evidence/phase_h/stress_25000/`](evidence/phase_h/stress_25000/) | 1,040 to 25,032 events; 0 kernel drops; 0 sequence gaps; 100.0% delivery up to 1,923.0 hooks/s |
| **EXP-3** | Controlled Buffer Saturation & Reader Backpressure (Phase H.2) | `96f36ce` | `sudo ./scripts/saturation_test.sh sat_16mb_8stream 16384 0 8 250`<br/>`sudo ./scripts/saturation_test.sh sat_bp_256kb 256 4 4 500`<br/>`sudo ./scripts/saturation_test.sh sat_bp_64kb 64 4 4 500` | 2,000 target events under 4.0-second induced userspace reader backpressure across buffer sizes (64KB, 256KB, 16MB) | [`evidence/phase_h2/suite1_capacity_8stream/`](evidence/phase_h2/suite1_capacity_8stream/)<br/>[`evidence/phase_h2/suite2_backpressure/`](evidence/phase_h2/suite2_backpressure/)<br/>[`evidence/phase_h2/original_unreconciled/`](evidence/phase_h2/original_unreconciled/) | Exact conservation: $\text{Hooks} = \text{Submissions} + \text{Drops}$. 64KB held 190 events during freeze; 256KB held 762 events (344B wire schema). Zero sequence gaps. |
| **EXP-4** | Execution-Path Semantics & Credential Transitions (Phase I) | `b8f70f5` | `sudo ./scripts/execution_path_test.sh` | 14 execution conditions: direct syscall, relative `execveat`, anonymous `memfd`, static ELF, symlinks, setuid EUID 0 transition, failed `ENOENT`/`EACCES`, and live cgroup migration | [`evidence/phase_i/execution_path_report.json`](evidence/phase_i/execution_path_report.json)<br/>[`evidence/phase_i/exec_paths_events.jsonl`](evidence/phase_i/exec_paths_events.jsonl) | 89 total events; 87 committed (`sched_process_exec`); 2 failed (`sys_exit_execve`); 0 drops; setuid `CG_FLAG_SETUID_EXEC` verified; cgroup migration tracked |
| **EXP-5A**| Detection Validation & False-Positive Evaluation (Phase I) | `7c56b1e` (Dataset 1)<br/>`b8f70f5` (Dataset 2) | `sudo ./scripts/detection_benchmark.sh` | Interleaved corpus: 120 benign operations (Git queries, multi-stage GCC compilation) vs 12 synthetic attack simulations | [`evidence/phase_i/detection_validation_report.json`](evidence/phase_i/detection_validation_report.json)<br/>[`evidence/phase_i/detection_alerts.jsonl`](evidence/phase_i/detection_alerts.jsonl) | Dataset 1 (133 events): TP=12, TN=387, FP=0, FN=0.<br/>Dataset 2 (132 events): TP=12, TN=384, FP=0, FN=0.<br/>100% Precision, 100% Recall on labelled suite. |
| **EXP-5B**| Monitoring Runtime Overhead & Resource Footprint (Phase I) | `7c56b1e` (Trial 1)<br/>`b8f70f5` (Trial 2) | `sudo ./scripts/overhead_benchmark.sh` | 2,000 rapid process executions across 4 worker streams with pre-test cache drops (`drop_caches`), comparing unmonitored vs ContainerGuard monitored | [`evidence/phase_i/overhead_benchmark_report.json`](evidence/phase_i/overhead_benchmark_report.json)<br/>[`evidence/phase_i/overhead_resource_samples.csv`](evidence/phase_i/overhead_resource_samples.csv) | Trial 1 (+3.46% overhead, 7.77 µs delta/lifecycle); Trial 2 (+5.95% overhead, 12.68 µs delta/lifecycle); Descriptive mean: 4.71%; Peak RSS: 6.04 MiB |

---

## 4. Step-by-Step Independent Reproduction Protocol

To independently execute and verify ContainerGuard without depending on pre-existing process or container state:

### Step 1: Clean Build Verification
```bash
# Verify no dirty state
git status

# Run the automated build script (non-destructive formatting verification)
./scripts/build.sh

# Confirm compiled hashes match official release
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
sudo ./scripts/execution_path_test.sh

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
*ContainerGuard 50% Verified Milestone Reproducibility Manifest*
