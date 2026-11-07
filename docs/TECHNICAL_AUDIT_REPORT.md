# ContainerGuard: Phase A Technical Implementation Audit Report

**Date:** 2026-11-07  
**Environment:** Linux 6.18.33.1-microsoft-standard-WSL2 (x86_64), Ubuntu 26.04 LTS, Go 1.26.8, Clang 21.1.8, bpftool v7.7.0 / libbpf v1.7.  
**Workspace:** `/home/ram/ebpf-smoke-test`  
**Git Baseline Commit:** `5199c92`

---

## 1. Inventory of Existing Artifacts and Sources

| Artifact / Source | Type / Role | Verified Status |
|---|---|---|
| `bpf-src/execve_events.c` | eBPF C source (tracepoint `sys_enter_execve`) | Compiles cleanly with Clang 21.1.8 (`-target bpf -g -O2 -I/usr/include/x86_64-linux-gnu`). Hash matches `execve_events.o`. |
| `execve_events.o` | Compiled BPF ELF 64-bit object | MD5: `ab5edb56fc1787d2e7b6b92795d86805`. Contains BTF, `.maps`, and tracepoint sections. |
| `bpf-src/execve_counter.c` | Historical BPF source | Simple counter map smoke test. Preserved. |
| `bpf-src/execve_tracepoint.c` | Historical BPF source | Minimal tracepoint probe smoke test. Preserved. |
| `container.go` | Go Docker & cgroup resolver | Resolves container metadata via `docker.ContainerInspect` and `/proc/<pid>/cgroup` inode. |
| `main.go` | Go userspace collector | Loads BPF object, starts resolver, polls Ring Buffer via `binary.Read`. |
| `containerguard-eventstream` | Precompiled binary | Size 12,923,068 bytes. Identical to `go build .` output. |
| `go.mod` / `go.sum` | Go module definitions | Module `cg-smoke-test`, `cilium/ebpf v0.22.0`, `moby/client v0.6.2`, `moby/api v1.56.1`. |

---

## 2. Kernel and Userspace Alignment Verification

### C eBPF Structure (`bpf-src/execve_events.c`):
```c
struct exec_event {
    __u64 timestamp_ns; // Offset 0, size 8
    __u64 cgroup_id;    // Offset 8, size 8
    __u32 tid;          // Offset 16, size 4
    __u32 tgid;         // Offset 20, size 4
    __u32 uid;          // Offset 24, size 4
    __u32 gid;          // Offset 28, size 4
    char comm[16];      // Offset 32, size 16
    char filename[256]; // Offset 48, size 256
}; // Total: 304 bytes. No compiler padding holes.
```

### Go Userspace Structure (`main.go`):
```go
type ExecEvent struct {
    TimestampNS uint64
    CgroupID    uint64
    TID  uint32
    TGID uint32
    UID  uint32
    GID  uint32
    Comm     [16]byte
    Filename [256]byte
} // Total: 304 bytes, little-endian.
```
Memory layout is aligned. However, decoding via `binary.Read(bytes.NewReader(record.RawSample), ...)` incurs unnecessary allocations and reflection overhead in hot loops.

---

## 3. Discovered Defects and Research Gaps

### Defect 1: Race Condition in Container Attribution (Critical Research Gap)
- **Mechanism:** When a new container is launched, its initial processes execute `sys_enter_execve` in kernel space instantaneously. The eBPF ring buffer submits the event to userspace in sub-millisecond time.
- **Problem:** The userspace Docker event listener (`mobyclient.Events`) receives the container "start" event asynchronously, and must then perform an HTTP/socket `ContainerInspect` roundtrip and file I/O on `/proc/<pid>/cgroup` to determine the cgroup v2 inode.
- **Observed Behavior:** The initial `execve` events arrive before the container mapping is present in `r.byCgroup`. The existing code permanently flags them as `HOST_OR_UNMAPPED`.
- **Solution Required:** Implement a stateful attribution model (`PENDING`, `RESOLVED`, `UNRESOLVED`, `STALE_MAPPING`, `HOST_CONFIRMED`) with bounded pending queues, lifecycle retry triggers, and timestamp-ordered reconciliation.

### Defect 2: Silent Event Loss in eBPF Ring Buffer (Zero Integrity Accounting)
- **Mechanism:** In `bpf-src/execve_events.c`:
  ```c
  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
      return 0;
  ```
- **Problem:** If ring buffer capacity is exhausted, the reservation returns `NULL`. The event is silently discarded with zero accounting.
- **Solution Required:** Implement atomic/per-CPU BPF accounting maps tracking:
  1. `HOOK_INVOCATIONS`
  2. `RINGBUF_RESERVE_FAILURES` (kernel drops)
  3. `SUBMITTED_EVENTS`
  4. Per-cgroup event counters.

### Defect 3: Hang on Shutdown Due to Blocking Ringbuf Reader
- **Mechanism:** In `main.go`, `reader.Read()` blocks waiting for kernel ring buffer epoll wakeups.
- **Problem:** When `SIGINT` or `SIGTERM` cancels `ctx`, `reader.Close()` is only reached after `reader.Read()` returns. If no execve occurs on the host, the process hangs indefinitely.
- **Solution Required:** Spawn an asynchronous context cancellation watcher that explicitly closes the reader on `<-ctx.Done()`.

### Defect 4: Single-Threaded Head-of-Line Blocking Pipeline
- **Mechanism:** `main.go` reads from ring buffer and immediately prints to stdout in a synchronous loop.
- **Problem:** Blocking I/O or downstream latency directly stalls ring buffer draining, artificially inducing kernel ring buffer overflows.
- **Solution Required:** Decouple ingestion, attribution, lineage tracking, and export into dedicated bounded channels.

### Defect 5: Host Attribution False Positives
- **Mechanism:** Root cgroup or unmapped processes default to `HOST_OR_UNMAPPED`.
- **Solution Required:** Read host root cgroup inode at startup to confirm `HOST_CONFIRMED`, distinguishing host processes from unmapped or pending container processes.
