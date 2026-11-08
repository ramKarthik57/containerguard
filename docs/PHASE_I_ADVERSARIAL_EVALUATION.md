# Phase I: Adversarial Telemetry, Process Identity, and Cgroup Migration Evaluation

**Document Status:** Empirical Evaluation Complete  
**Date:** 2026-11-08  
**Kernel:** Linux 6.18.33.1-microsoft-standard-WSL2 (x86_64, PREEMPT_DYNAMIC)  
**Binary Builds:**  
- `bin/containerguard`: Go Daemon v0.9.0  
- `bpf/execve_events.o`: Multi-Tracepoint eBPF Telemetry Engine  

---

## 1. Executive Summary

Phase I addresses fundamental resilience requirements for eBPF runtime security monitors operating in adversarial Linux container environments:
1. **Decoupling Process Identity from Execution Context:** Separating immutable process identity (`TGID`, `group_leader->start_time`) from mutable cgroup associations (`cgroup_id`), preventing lineage fragmentation when processes migrate across cgroups.
2. **Kernel Parent Cgroup Resolution:** Eliminating userspace parent cgroup assumptions by independently resolving the parent process's actual cgroup inode (`parent_leader->cgroups->dfl_cgrp->kn->id`) via BPF CO-RE.
3. **Adversarial Telemetry Invariants:** Accurately detecting and handling path truncations (>256 bytes), comm truncations (15+ bytes), memfd anonymous executions (`AT_EMPTY_PATH`), and PID recycling.
4. **Conservation Under Adversarial Workloads:** Maintaining exact telemetry conservation ($\text{Hook Calls} = \text{Submissions} + \text{Reservation Drops}$) across all execution permutations.

---

## 2. Process Identity Architecture & Cgroup Migration Audit

### 2.1 The Process Identity Problem in Linux Containers

Prior to Phase I, ContainerGuard defined process identity as:
```go
type ProcessKey struct {
    CgroupID    uint64
    TGID        uint32
    StartTimeNS uint64
}
```
Furthermore, the child process copied its own observed `CgroupID` into the parent's key:
```go
parentKey := ProcessKey{
    CgroupID:    raw.CgroupID, // Defect: Assumed parent shares child's cgroup!
    TGID:        raw.ParentTGID,
    StartTimeNS: raw.ParentStartTimeNS,
}
```

This design suffered from two architectural vulnerabilities:
1. **Cross-Cgroup Lineage Breakage:** When a container is launched, the parent runtime process (`containerd-shim` or `runc`) resides in the system/host cgroup slice (e.g. `cgroup_id = 1`), while the child entrypoint executes inside the container's isolated cgroup slice (e.g. `cgroup_id = 999`). Copying `raw.CgroupID` caused the lineage tracker to look for the parent in the container slice, permanently breaking process ancestry.
2. **Cgroup Migration Fragmentation:** If a long-running process is moved between cgroups (e.g., systemd moving a worker between slices, or Docker updating container resource constraints via `cgroup.procs`), its `TGID` and `start_time` remain constant, but its `cgroup_id` changes. Under the naive key, subsequent executions appeared as an unrelated process, fracturing execution history.

### 2.2 Decoupled Identity Model

In Linux, a thread group leader's `start_time` (stored in nanoseconds since boot) is immutable across the lifetime of the process. Even if the process executes new binaries (`execve`), changes namespaces, or migrates between cgroups, `(tgid, start_time_ns)` remains strictly invariant.

Phase I implements a two-tier identity architecture:
```go
// ProcessInstanceKey: Immutable process identity invariant to cgroup migration
type ProcessInstanceKey struct {
    TGID        uint32 `json:"tgid"`
    StartTimeNS uint64 `json:"start_time_ns"`
}

// ProcessKey: Context-aware tuple combining immutable identity with current execution context
type ProcessKey struct {
    CgroupID    uint64 `json:"cgroup_id"`
    TGID        uint32 `json:"tgid"`
    StartTimeNS uint64 `json:"start_time_ns"`
}
```

In `internal/lineage/lineage.go`, processes are indexed by `ProcessInstanceKey`. When a process executes in a new cgroup:
1. The tracker recognizes the existing `ProcessInstanceKey`.
2. It detects that `node.Key.CgroupID != event.CgroupID`.
3. It preserves the previous cgroup in `node.CgroupHistory`.
4. It updates the current context and flags `CG_FLAG_CGROUP_MIGRATED`.

### 2.3 Independent Kernel Parent Cgroup Resolution

In `bpf/execve_events.c`, the kernel probe now directly traverses the parent process task structure via BPF CO-RE:
```c
struct task_struct *parent = BPF_CORE_READ(task, real_parent);
if (parent) {
    struct task_struct *parent_leader = BPF_CORE_READ(parent, group_leader);
    if (!parent_leader)
        parent_leader = parent;

    parent_start_time = BPF_CORE_READ(parent_leader, start_time);
    parent_tgid = BPF_CORE_READ(parent_leader, tgid);
    parent_cgroup_id = BPF_CORE_READ(parent_leader, cgroups, dfl_cgrp, kn, id);
}
```
This guarantees that `event.ParentCgroupID` reflects the parent's actual cgroup inode at execution time.

---

## 3. Empirical Cgroup Migration Validation

To empirically validate cgroup migration tracking under live kernel conditions, the test harness (`scripts/execution_path_test.sh`):
1. Created two isolated cgroup v2 directories:
   - `/sys/fs/cgroup/cg_mig_test_grp1`
   - `/sys/fs/cgroup/cg_mig_test_grp2`
2. Launched a dedicated process and placed it into `cg_mig_test_grp1`.
3. Executed binary `/bin/true` in cgroup 1.
4. Migrated the running process to `cg_mig_test_grp2` via `/sys/fs/cgroup/cg_mig_test_grp2/cgroup.procs`.
5. Executed `/bin/true` in cgroup 2.

### Observed Live Telemetry
- **Pre-Migration:**
  - TGID: `112264`
  - Start Time: `1607519124230`
  - Cgroup ID: `1421` (`cg_mig_test_grp1`)
- **Post-Migration:**
  - TGID: `112264` (Invariant)
  - Start Time: `1607519124230` (Invariant)
  - Cgroup ID: `1422` (`cg_mig_test_grp2`)
  - Flag: `cgroup_migrated: true`
  - Lineage: Successfully unified under a single `ProcessNode` with `CgroupHistory: [1421]`.

---

## 4. Adversarial Telemetry Invariants & Boundary Stress

The test harness evaluated adversarial edge cases designed to bypass or corrupt eBPF telemetry:

| Adversarial Vector | Test Implementation | Observed Telemetry | Assessment |
| :--- | :--- | :--- | :--- |
| **Pathname Truncation** | Deeply nested directory path (> 350 bytes) | `path_truncated: true`, path truncated safely at 255 bytes + `\0` | **Passed** |
| **Comm Truncation** | Process comm padded to 16 bytes via `prctl(PR_SET_NAME)` | `comm_truncated: true` | **Passed** |
| **Anonymous Memfd (`AT_EMPTY_PATH`)** | ELF binary copied into anonymous `memfd`, executed via `execveat(fd, "", AT_EMPTY_PATH)` | `at_empty_path: true`, `execveat: true`, filename resolved to `anon_elf_true` via `sched_process_exec` | **Passed** |
| **Failed Execution: ENOENT** | Attempted execution of nonexistent file `/tmp/nonexistent_xyz_9999` | `failed: true`, `exit_code: -2`, exactly 1 event emitted | **Passed** |
| **Failed Execution: EACCES** | Attempted execution of script without `+x` permissions (`chmod 0644`) | `failed: true`, `exit_code: -13`, exactly 1 event emitted | **Passed** |
| **PID Recycling** | Sequential processes created with reused PIDs | Disambiguated by nanosecond `start_time_ns` without node collision | **Passed** |

---

## 5. Telemetry Conservation Under Adversarial Permutations

During the execution path and adversarial test suite:
$$\text{Kernel Hook Calls} = 72$$
$$\text{Kernel Submissions} = 72$$
$$\text{Kernel Reserve Drops} = 0$$
$$\text{Userspace Decoded Records} = 72$$
$$\text{Conservation Equation: } 72 = 72 + 0 \quad (100.00\%)$$
$$\text{Telemetry Delivery Rate: } \frac{72}{72} \times 100.0\% = 100.00\%$$

Zero sequence gaps were observed (`sequence_gaps_detected: 0`), and the attribution pending queue drained cleanly to 0 on shutdown.
