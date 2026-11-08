# ContainerGuard: Build, Installation & Verification Manual

**Release Milestone:** ContainerGuard 50% Verified Milestone  
**Target Environment:** Linux 6.x+ x86_64 with BTF and cgroup v2 enabled  
**Validated Hardware/OS:** Ubuntu 26.04.1 LTS on WSL2 (`Linux 6.18.33.1-microsoft-standard-WSL2`, x86_64)

---

## 1. System Requirements & Prerequisites

To compile eBPF bytecode, build the Go daemon, and execute validation workloads, the host system must meet the following software requirements:

| Component | Minimum Version | Validated Version | Required Capabilities / Purpose |
| :--- | :--- | :--- | :--- |
| **Linux Kernel** | Modern 6.x (theoretical $\ge 5.8$) | `6.18.33.1` (WSL2) | Kernel BTF (`/sys/kernel/btf/vmlinux`), cgroup v2 unified hierarchy, BPF ring buffer support (`BPF_MAP_TYPE_RINGBUF`). *Note: Validated on 6.18.33.1; compatibility across other 6.x releases is not independently verified.* |
| **Clang / LLVM** | $\ge 14.0$ | `21.1.8` | BPF target compiler (`clang -target bpf`) with CO-RE debug generation (`-g`) |
| **Go Toolchain** | $\ge 1.26.8$ | `1.26.8` | CGO-free userspace daemon compilation (per `go.mod` directive) |
| **Docker Engine** | $\ge 24.0$ | `29.9.3` | Container discovery and cgroup inode reconciliation (`/var/run/docker.sock`) |
| **libbpf Headers** | $\ge 1.0$ | `1.5.0` | Upstream helper definitions (`<bpf/bpf_helpers.h>`, `<bpf/bpf_core_read.h>`) |
| **System Tools** | — | Standard GNU | `bpftool`, `gcc`, `make`, `tar`, `curl`, `jq` |

### Verifying Host Capabilities
```bash
# 1. Verify BTF availability
ls -l /sys/kernel/btf/vmlinux

# 2. Verify unified cgroup v2 hierarchy
mount | grep cgroup2

# 3. Verify Docker runtime status
docker version
```

---

## 2. Compilation Instructions

The build process is automated via [`scripts/build.sh`](scripts/build.sh), or can be executed as individual compilation steps.

> [!NOTE]
> Running `./scripts/build.sh` compiles by default into an isolated output directory (`build/bin/` and `build/bpf/`). It computes the resulting SHA-256 digests and checks them against official milestone hashes while preserving the tracked release binaries (`bin/containerguard`, `bpf/execve_events.o`) unmodified. Pass `--overwrite-release` to explicitly write to `bin/` and `bpf/`.

### Step 1: Compile eBPF Kernel Program
The eBPF program is compiled into a CO-RE (Compile Once – Run Everywhere) ELF 64-bit object. It embeds BTF type information, enabling dynamic offset relocation against the running kernel. To prevent overwriting the tracked milestone release binaries, compile into `build/bpf/`:
```bash
mkdir -p build/bpf build/bin
clang -g -O2 -target bpf \
  -D__TARGET_ARCH_x86 \
  -I/usr/include/x86_64-linux-gnu \
  -c bpf/execve_events.c \
  -o build/bpf/execve_events.o
```

**Verification:** Confirm that the output object contains valid eBPF bytecode and maps:
```bash
llvm-objdump -h build/bpf/execve_events.o
```

### Step 2: Format and Lint Go Source
Verify source compliance before compilation:
```bash
gofmt -l .
go vet ./...
```

### Step 3: Compile Userspace Control Plane
Compile the ContainerGuard daemon binary into `build/bin/`:
```bash
go build -o build/bin/containerguard ./cmd/containerguard
```

### Step 4: Verify Cryptographic Checksums
Confirm the digests of the newly compiled development binaries, and compare them with the official release digests:
```bash
# Newly compiled build artifacts:
sha256sum build/bin/containerguard build/bpf/execve_events.o

# Official frozen milestone release artifacts (immutable at b8f70f5):
sha256sum bin/containerguard bpf/execve_events.o
```
*Official Milestone Hashes (Commit `b8f70f5`):*
- `bin/containerguard`: `cfee0d9675b653fdd7cda2629454a4839b1fd59ede0ba43f8bcd7ce7bebc93d0`
- `bpf/execve_events.o`: `6ae519a012694f11c9ab514c1b13cafb4b8551fb8deadaf10dee817862717ef3`

---

## 3. Test Suite Execution

ContainerGuard provides automated tests ranging from fast, unprivileged unit tests to privileged live kernel integration tests.

### A. Unprivileged Unit Tests (No Root Required)
These tests validate binary decoding, lineage tracking, process identity decoupling, attribution buffer timeouts, and detection rule logic in user space:
```bash
./scripts/test.sh
```
Or run individual test suites with coverage:
```bash
go test -v -count=1 ./internal/container
go test -v -count=1 ./internal/detection
go test -v -count=1 ./internal/lineage
go test -v -count=1 ./internal/pipeline
go test -v -count=1 ./internal/telemetry
```

---

## 4. Live System Execution & Privilege Guidelines

### Privilege Requirements & Safety Notice
> [!IMPORTANT]
> Running the ContainerGuard daemon requires administrative privileges (`CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_PERFMON`, and read access to `/var/run/docker.sock`).
> - **Always use normal interactive `sudo` authentication.**
> - **Never configure passwordless sudo (`NOPASSWD: ALL`).**
> - **Do not add unprivileged users to the `docker` group in production environments.**

### Launching the Daemon
Run the daemon interactively with standard parameters (using either the newly built development binary or the frozen release binary):
```bash
# Option A: Run newly built development binary (build/)
sudo ./build/bin/containerguard \
  -bpf build/bpf/execve_events.o \
  -metrics-interval 5s \
  -pending-ttl 2s

# Option B: Run official frozen milestone binary (bin/ and bpf/)
sudo ./bin/containerguard \
  -bpf bpf/execve_events.o \
  -metrics-interval 5s \
  -pending-ttl 2s
```

### File-Based Audit Logging
To persist captured events and security alerts to structured JSONL streams:
```bash
sudo ./build/bin/containerguard \
  -bpf build/bpf/execve_events.o \
  -events-log /tmp/cg_events.jsonl \
  -alerts-log /tmp/cg_alerts.jsonl \
  -metrics-interval 5s
```

---

## 5. Reproducing Research Experiments

The repository includes standalone automated benchmark and test runners used to generate the empirical evidence reports:

### 1. Execution-Path Coverage Verification (Phase I)
Builds test binaries and evaluates 14 execution pathways (shebang scripts, relative `execveat`, anonymous `memfd` via `AT_EMPTY_PATH`, symlinks, static binaries, setuid privilege escalation, and failed executions):
```bash
# Option A: Evaluate historical baseline archive in archive mode (non-destructive, no root required):
./scripts/execution_path_test.sh --archive-eval

# Option B: Live reproduction run (requires interactive root privileges):
# Execute directly as an unprivileged user (not with sudo). The script uses sudo
# internally for daemon and cgroup operations, and compiles an ephemeral setuid helper
# inside the run directory to test the genuine unprivileged UID 1000 -> EUID 0 transition
# without modifying the tracked release binary bin/cg_setuid_test.
./scripts/execution_path_test.sh
```
*Report Output:* [`docs/EXECUTION_PATH_COVERAGE.md`](docs/EXECUTION_PATH_COVERAGE.md)  
*Preserved Baseline Evidence:* [`docs/evidence/phase_i/execution_path_report.json`](docs/evidence/phase_i/execution_path_report.json), [`docs/evidence/phase_i/exec_paths_events.jsonl`](docs/evidence/phase_i/exec_paths_events.jsonl) (frozen at milestone `b8f70f5`)  
*Live Reproduction Runs:* Saved by default to timestamped subdirectories under `docs/evidence/phase_i/runs/<run_id>/`

### 2. Detection Validation & Confusion Matrix
Executes 120 benign developer operations (GCC compilation, Git status queries, container diagnostics) and 12 synthetic attack simulations:
```bash
sudo ./scripts/detection_benchmark.sh
```
*Report Output:* [`docs/DETECTION_VALIDATION.md`](docs/DETECTION_VALIDATION.md)  
*Raw Evidence:* [`docs/evidence/phase_i/detection_events.jsonl`](docs/evidence/phase_i/detection_events.jsonl)

### 3. Monitoring Overhead Benchmarking
Executes 2,000 concurrent process lifecycles across 4 streams with and without monitoring to calculate amortized execution overhead:
```bash
sudo ./scripts/overhead_benchmark.sh 2000 4
```
*Report Output:* [`docs/OVERHEAD_EVALUATION.md`](docs/OVERHEAD_EVALUATION.md)  
*Raw Evidence:* [`docs/evidence/phase_i/overhead_benchmark_report.json`](docs/evidence/phase_i/overhead_benchmark_report.json)

### 4. Telemetry Stress Testing (Phase H)
Evaluates ring buffer delivery under load tiers (1,000 to 25,000 events):
```bash
sudo ./scripts/stress_test.sh 1000
sudo ./scripts/stress_test.sh 5000
sudo ./scripts/stress_test.sh 10000
sudo ./scripts/stress_test.sh 25000
```
*Report Output:* [`docs/STRESS_TEST_RESULTS.md`](docs/STRESS_TEST_RESULTS.md)

### 5. Controlled Saturation & Backpressure Testing (Phase H.2)
Deliberately induces kernel reservation drops via reader backpressure to verify mathematical conservation ($\text{Hooks} = \text{Submissions} + \text{Drops}$):
```bash
# 16 MiB buffer absorbs burst without drops
sudo ./scripts/saturation_test.sh sat_bp_16mb 16384 4 4 500

# 256 KiB buffer saturates and drops ~1,300 events
sudo ./scripts/saturation_test.sh sat_bp_256kb 256 4 4 500

# 64 KiB buffer saturates and drops ~1,870 events
sudo ./scripts/saturation_test.sh sat_bp_64kb 64 4 4 500
```
*Report Output:* [`docs/SATURATION_EVALUATION.md`](docs/SATURATION_EVALUATION.md)

---

## 6. Troubleshooting & Diagnostics

| Symptom | Probable Cause | Diagnostic Command & Remediation |
| :--- | :--- | :--- |
| `permission denied` accessing `/sys/kernel/btf/vmlinux` | Insufficient privileges | Verify execution with `sudo`; confirm kernel configuration has `CONFIG_DEBUG_INFO_BTF=y`. |
| `failed to load BPF object: operation not permitted` | Missing `CAP_BPF` or `CAP_SYS_ADMIN` | Ensure process has root privileges or adequate capabilities. |
| `connecting to Docker Engine: permission denied` | Accessing `/var/run/docker.sock` | Confirm Docker daemon is active (`sudo systemctl status docker`) and user has access via sudo. |
| `ring buffer reserve failed (drops reported)` | Buffer capacity exhausted | Expected under high backpressure with small buffers. Increase `-ringbuf-size-kb` (default 16384 KiB). |
| `failed to find cgroup inode` | Cgroup v1 or non-unified mode | Ensure host is mounted with unified cgroup v2 (`mount -t cgroup2`). |

---

## 7. Build Provenance & Module Specification

- **Module Identity (`go.mod`):** The repository's Go module is declared as `module cg-smoke-test`. This identifier reflects the prototype origin of the initial codebase and is strictly preserved in the frozen 50% milestone to guarantee bit-for-bit checksum parity of compiled binary symbols (`bin/containerguard`) against the release checkpoint (`b8f70f5`).
- **Continuous Integration Workflow Template:** A non-destructive CI configuration template is provided at [`.github/ci-workflow-template.yml`](.github/ci-workflow-template.yml), executing non-mutating `gofmt` verification, `go vet`, race-enabled unit testing, and relative link crawling.
- **Experiment Provenance Manifest:** For end-to-end execution commands, parameters, environment metadata, and raw evidence links across all benchmark experiments, see the [Experiment Provenance Manifest](docs/EXPERIMENT_PROVENANCE_MANIFEST.md).

---
*ContainerGuard 50% Verified Milestone Build Manual*
