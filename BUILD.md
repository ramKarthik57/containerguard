# Building and Running ContainerGuard

## Prerequisites

- **Host/Kernel:** Linux kernel 6.x+ with BPF Ring Buffer and cgroup v2 enabled.
- **Compiler:** Clang / LLVM (tested with Clang 21.1.8).
- **Go Toolchain:** Go 1.22+ (tested with Go 1.26.8).
- **BPF Utilities:** `bpftool`, `libbpf-dev`, Linux headers.
- **Container Runtime:** Docker Engine (tested with Docker 29.9.3, containerd 2.4.2).

---

## 1. Automated Build

Execute the build script:
```bash
./scripts/build.sh
```
This produces:
- `bpf/execve_events.o`: ELF 64-bit eBPF object with BTF and accounting maps.
- `bin/containerguard`: Compiled userspace intrusion detection daemon.

---

## 2. Running Automated Tests

Run the full Go test suite:
```bash
./scripts/test.sh
```
Or run individual package tests:
```bash
go test -v ./internal/telemetry
go test -v ./internal/container
go test -v ./internal/pipeline
go test -v ./internal/lineage
go test -v ./internal/detection
```

---

## 3. Running ContainerGuard Daemon

Run the daemon as root (or with `CAP_BPF`, `CAP_SYS_ADMIN`, and access to `/var/run/docker.sock`):
```bash
sudo ./bin/containerguard \
  -bpf bpf/execve_events.o \
  -metrics-interval 5s \
  -pending-ttl 2s
```

Optional audit logging flags:
```bash
sudo ./bin/containerguard \
  -bpf bpf/execve_events.o \
  -events-log /tmp/cg_events.jsonl \
  -alerts-log /tmp/cg_alerts.jsonl
```
