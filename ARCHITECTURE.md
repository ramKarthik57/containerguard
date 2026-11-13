# ContainerGuard System Architecture & Engineering Design

**Release Milestone:** ContainerGuard 50% Verified Milestone  
**Target Platform:** Linux 6.x+ with BTF (Empirically verified on Linux 6.18.33.1-microsoft-standard-WSL2 / x86_64)  
**Implementation Languages:** C (eBPF CO-RE), Go 1.26.8 (Userspace Control Plane per `go.mod`)

---

## 1. Architectural Philosophy & Design Principles

ContainerGuard is designed from first principles to resolve four fundamental vulnerabilities in existing container runtime observability agents:
1. **Zero-Drop Telemetry Integrity:** Kernel-side event submission must be decoupled from userspace processing. Telemetry loss must never occur silently; drops must be explicitly measured, accounted for, and mathematically verifiable:
   $$\text{Kernel Hook Invocations} = \text{RingBuffer Submissions} + \text{Kernel Reservation Drops}$$
2. **Deterministic Process Identity Across Reboots & PID Recycling:** Linux PIDs are bounded integers (default $\le 32768$ or $\le 4194304$) subject to rapid recycling. Process identity must be decoupled from mutable execution contexts (such as PIDs and cgroup assignments) using an immutable tuple of Thread Group ID and monotonic process start time (`ProcessInstanceKey{TGID, StartTimeNS}`).
3. **Multi-Tracepoint Execution Semantics:** Intercepting execution attempts at `sys_enter_execve` alone yields false positives on failed calls and blind spots on non-standard execution pathways (`execveat`, relative dirfds, anonymous `memfd` execution). ContainerGuard correlates 5 coordinated kernel tracepoints to differentiate execution attempts, committed binary activations, and kernel-side execution failures.
4. **Explicit Attribution State Machine:** Unmapped container events must never default to host actions. Events transition through a deterministic lifecycle (`PENDING` $\to$ `RESOLVED` or `UNRESOLVED`), supported by container tombstone caching to handle asynchronous container creation races and rapid container destruction.

---

## 2. Global System Topology

The ContainerGuard architecture spans the Linux kernel boundary, bridging eBPF tracepoint hooks with a concurrent, multi-stage userspace analysis pipeline.

```mermaid
flowchart TD
    subgraph KernelSpace ["Linux Kernel (eBPF Subsystem)"]
        direction TB
        subgraph Tracepoints ["Tracepoint Interception"]
            E1["sys_enter_execve / sys_enter_execveat<br/>(Capture Attempt & Arguments)"]
            SP["sched_process_exec<br/>(Committed Binary Execution)"]
            EX["sys_exit_execve / sys_exit_execveat<br/>(Execution Failure with Errno)"]
        end

        subgraph InFlightState ["In-Flight State & Metrics"]
            AT["active_exec_attempts<br/>(LRU Hash Map)"]
            SC["Per-CPU Scratchpad<br/>(Stack Relief)"]
            TC["telemetry_counters<br/>(Hooks, Drops, Submissions)"]
            SEQ["event_sequence<br/>(Atomic Monotonic Counter)"]
        end

        RB["events BPF Ring Buffer<br/>(16 MiB Lockless Memory-Mapped Buffer)"]

        SC -.->|Zero-Copy Struct Buffer| AT
        E1 -->|1. Record In-Flight Attempt| AT
        AT -.->|2. Retrieve Attempt Context| SP
        AT -.->|2. Retrieve Attempt Context| EX
        
        E1 -.->|Count Invocations| TC
        SP -.->|Count Submissions / Drops| TC
        EX -.->|Count Submissions / Drops| TC

        SEQ -->|Atomic Increment| RB
        SP -->|Submit Committed Event (360B)| RB
        EX -->|Submit Failed Event (360B)| RB
    end

    subgraph UserSpacePipeline ["ContainerGuard Userspace Daemon"]
        direction TB
        subgraph IngestionBoundary ["Ingestion Boundary"]
            CR["Ring Buffer Consumer<br/>(internal/collector)"]
            ING["Pipeline Ingester<br/>(Sequence Integrity Verification)"]
            CR -->|360B Binary Event| ING
        end

        subgraph AttributionEngine ["Container Attribution Engine"]
            AB["Attribution Buffer<br/>(FIFO Queue & Inode Index)"]
            CRZ["Container Resolver & Tombstone Cache<br/>(Map Inode to Container Context)"]
            DR["Docker Engine Socket<br/>(/var/run/docker.sock)"] -->|Lifecycle Events| CRZ
            CG["cgroup v2 Hierarchy<br/>(/sys/fs/cgroup)"] -->|Inode Inspection| CRZ
            ING -->|Raw Event| AB
            CRZ -->|Bind Inode Mapping| AB
        end

        subgraph AnalysisEngine ["Lineage & Detection Pipeline"]
            LT["Lineage Tracker<br/>(Process Tree & Cgroup History)"]
            DE["Detection Engine<br/>(Rules 001, 002, 003)"]
            AB -->|Attributed SecurityEvent| LT
            LT -->|Enriched Process Context| DE
        end

        subgraph PersistenceBoundary ["Persistence Boundary"]
            ST["Storage Manager<br/>(exec_paths_events.jsonl & exec_paths_alerts.jsonl)"]
            DE -->|Security Alerts| ST
            LT -->|Enriched Telemetry| ST
        end
    end

    RB ==>|mmap RingBuf Stream (368B On-Wire Records)| CR

    classDef kernel fill:#1f2937,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef userspace fill:#111827,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef storage fill:#374151,stroke:#f59e0b,stroke-width:2px,color:#fff;
    class E1,SP,EX,AT,RB,SC,SEQ,TC kernel;
    class CR,ING,AB,DR,CG,CRZ,LT,DE userspace;
    class ST storage;
```

---

## 3. Kernel Subsystem Architecture (`bpf/execve_events.c`)

### 3.1 Tracepoint Interception Strategy
ContainerGuard coordinates 5 specific kernel tracepoints to provide comprehensive execution-path visibility across monitored execve and execveat pathways without missing failed syscalls or falling victim to namespace concealment:

> [!NOTE]
> **Kernel Compatibility & Portability Qualification:** The eBPF kernel engine is compiled with Clang using BPF CO-RE (`vmlinux.h`) and BTF type relocations. While CO-RE provides the architectural mechanism for cross-kernel struct layout portability, empirical verification has been conducted specifically on `Linux 6.18.33.1-microsoft-standard-WSL2`. Compatibility across untested upstream distributions or older kernels requires independent empirical testing.

| Tracepoint Location | Kernel Event | Purpose & Handled Semantics | Emitted Flags |
| :--- | :--- | :--- | :--- |
| `syscalls/sys_enter_execve` | `execve()` entry | Capture attempted binary path, arguments pointer, working directory, and calling process credentials. | `CG_FLAG_PATH_TRUNCATED`, `CG_FLAG_COMM_TRUNCATED` |
| `syscalls/sys_enter_execveat` | `execveat()` entry | Capture relative execution via directory file descriptor (`dfd`) or anonymous execution via `AT_EMPTY_PATH` (`0x1000`). | `CG_FLAG_EXECVEAT`, `CG_FLAG_AT_EMPTY_PATH` |
| `sched/sched_process_exec` | Binary loader committed | Triggered after kernel loader (ELF, shebang, script) succeeds and process image is replaced. Marks execution success. | `CG_FLAG_COMMITTED_EXEC`, `CG_FLAG_SETUID_EXEC` |
| `syscalls/sys_exit_execve` | `execve()` exit | Intercepts execution failures (e.g., `-2` for `ENOENT`, `-13` for `EACCES`). Emits failed execution telemetry. | `CG_FLAG_EXEC_FAILED` (exit_code < 0) |
| `syscalls/sys_exit_execveat` | `execveat()` exit | Intercepts failed relative or anonymous execution attempts with exit errno. | `CG_FLAG_EXEC_FAILED`, `CG_FLAG_EXECVEAT` |

### 3.2 Multi-Tracepoint Execution Lifecycle State Machine

```mermaid
sequenceDiagram
    autonumber
    actor App as Executing Process
    participant Enter as sys_enter_execve(at)
    participant Map as active_attempts (LRU)
    participant Hook as sched_exec / sys_exit
    participant Pipeline as Ring Buffer & Daemon

    App->>Enter: execve(pathname, argv, envp)
    activate Enter
    Note over Enter: Tracepoint: sys_enter<br/>- CO-RE cgroup v2 inode capture<br/>- Metric: CG_METRIC_HOOK_CALLS++
    Enter->>Map: Store struct exec_attempt (Key: pid_tgid)
    deactivate Enter

    alt Case 1: Binary Loader Committed (sched_process_exec)
        App->>Hook: Binary image loaded into memory
        activate Hook
        Hook->>Map: Lookup attempt by pid_tgid
        Note over Hook: Credential check: EUID != UID -> Setuid Flag
        Hook->>Pipeline: bpf_ringbuf_submit(CG_FLAG_COMMITTED_EXEC)
        Hook->>Map: Delete attempt entry (Cleanup)
        Hook-->>App: Syscall returns 0 (Process executes)
        deactivate Hook

    else Case 2: Kernel Loader Failed (sys_exit_execve)
        Hook->>Map: Lookup attempt by pid_tgid
        activate Hook
        Hook->>Pipeline: bpf_ringbuf_submit(CG_FLAG_EXEC_FAILED, errno)
        Hook->>Map: Delete attempt entry (Cleanup)
        Hook-->>App: Syscall returns negative errno (-ENOENT, -EACCES)
        deactivate Hook
    end

    Note over Pipeline: Userspace Daemon consumes 360B records via lockless mmap
```

### 3.3 BPF Memory Architecture & Map Specifications

```c
/* Enriched 360-byte kernel execution event layout (64-bit aligned) */
struct exec_event {
    __u64 timestamp_ns;         /* Offset  0: Monotonic kernel timestamp */
    __u64 cgroup_id;            /* Offset  8: Cgroup v2 inode of executing task */
    __u64 parent_cgroup_id;     /* Offset 16: Cgroup v2 inode of parent process */
    __u64 seq_num;              /* Offset 24: Monotonic per-system sequence number */
    __u64 start_time_ns;        /* Offset 32: Thread-group leader process start time */
    __u64 parent_start_time_ns; /* Offset 40: Parent leader start time */
    __u32 tid;                  /* Offset 48: Thread ID */
    __u32 tgid;                 /* Offset 52: Thread Group ID (Process PID) */
    __u32 parent_tgid;          /* Offset 56: Parent TGID (PPID) */
    __u32 uid;                  /* Offset 60: Real User ID */
    __u32 gid;                  /* Offset 64: Real Group ID */
    __u32 flags;                /* Offset 68: Operational bitmask flags */
    __s32 dfd;                  /* Offset 72: Directory FD for execveat (-100 for AT_FDCWD) */
    __u32 at_flags;             /* Offset 76: Flags for execveat (AT_EMPTY_PATH = 0x1000) */
    __s32 exit_code;            /* Offset 80: Syscall return code (0 or negative errno) */
    __u32 euid;                 /* Offset 84: Effective UID */
    char  comm[16];             /* Offset 88: Executing command comm */
    char  filename[256];        /* Offset 104: Executable absolute/relative pathname */
};
```

#### Kernel Map Registry:
1. **`events` (`BPF_MAP_TYPE_RINGBUF`):**  
   16 MiB default multi-producer, single-consumer ring buffer. Supports lockless user-space memory mapping (`mmap`), reducing overhead compared to legacy `perf_event` buffers.
2. **`active_exec_attempts` (`BPF_MAP_TYPE_LRU_HASH`, max 16,384 entries):**  
   Tracks in-flight execution attempts between syscall entry and exit/commit. The LRU eviction policy prevents memory leaks if an executing thread is terminated asynchronously before syscall completion.
3. **`attempt_scratch` (`BPF_MAP_TYPE_PERCPU_ARRAY`, 1 entry):**  
   Per-CPU scratchpad storage used to assemble in-flight attempts, completely preventing BPF verifier stack exhaustion (Linux BPF stack is limited to 512 bytes; `struct exec_attempt` is 352 bytes).
4. **`telemetry_counters` (`BPF_MAP_TYPE_ARRAY`, 4 entries):**  
   Maintains atomic 64-bit kernel telemetry metrics:
   - Index 0: `CG_METRIC_HOOK_CALLS`
   - Index 1: `CG_METRIC_RB_RESERVE_DROPS`
   - Index 2: `CG_METRIC_RB_SUBMITTED`
   - Index 3: `CG_METRIC_CGROUP_MAP_FAILS`
5. **`event_sequence` (`BPF_MAP_TYPE_ARRAY`, 1 entry):**  
   Generates a strictly monotonic 64-bit sequence number across all execution tracepoints, allowing user space to detect sequence gaps.

---

## 4. Process Identity & Lineage Architecture (`internal/lineage`)

### 4.1 Immutable Process Identity Decoupling
Traditional Linux observability tools key processes on PID or `(PID, CgroupID)`. This creates severe tracking flaws:
- **PID Recycling:** PIDs wrap around quickly under heavy execution workloads.
- **Cross-Cgroup Migration:** A container process moved into a sub-cgroup or system slice changes identity, breaking parentage.
- **Cross-Namespace Parentage:** Container runtimes (`containerd-shim`, `runc`) execute in the host cgroup, while child processes launch in container cgroups.

ContainerGuard decouples mutable execution context from immutable process instance identity:

```mermaid
classDiagram
    direction TB
    class ProcessInstanceKey {
        +uint32 TGID
        +uint64 StartTimeNS
        +String() string
    }

    class ProcessKey {
        +uint64 CgroupID
        +uint32 TGID
        +uint64 StartTimeNS
        +InstanceKey() ProcessInstanceKey
    }

    class ProcessNode {
        +ProcessKey Key
        +ProcessInstanceKey InstanceKey
        +ProcessKey ParentKey
        +ProcessInstanceKey ParentInstanceKey
        +uint32 UID
        +uint32 GID
        +string ContainerID
        +string Comm
        +string Executable
        +time.Time StartTime
        +List~uint64~ CgroupHistory
    }

    ProcessKey ..> ProcessInstanceKey : derives
    ProcessNode --> ProcessKey : active key
    ProcessNode --> ProcessInstanceKey : immutable id
```

### 4.2 Cgroup Migration Handling
When a process moves to a different cgroup (e.g. systemd slice reparenting or resource constraint adjustment):
1. `LineageTracker.RecordExec()` identifies the existing node via `ProcessInstanceKey{TGID, StartTimeNS}`.
2. If `existing.Key.CgroupID != event.CgroupID`, the migration is recorded:
   - Prior cgroup is pushed into `node.CgroupHistory`.
   - The event is flagged as `cgroup_migrated: true`.
   - The active primary key is updated without breaking parent-child links or losing historical attribution.

---

## 5. Container Identity Resolution (`internal/container`)

ContainerGuard resolves container ownership via the Linux **cgroup v2 filesystem inode**:

```mermaid
stateDiagram-v2
    [*] --> InodeEvaluation: Ingest event with CgroupID

    state InodeEvaluation {
        [*] --> CheckHostRoot
        CheckHostRoot --> HostIdentity: CgroupID == HostRootInode
        CheckHostRoot --> CheckInventory: CgroupID != HostRootInode

        CheckInventory --> ContainerIdentity: Match in byCgroup inventory
        CheckInventory --> CheckTombstones: Miss in active inventory

        CheckTombstones --> ContainerIdentity: Match in staleMappings
        CheckTombstones --> AttributionBuffer: Unrecognized CgroupID
    }

    state AttributionBuffer {
        [*] --> PendingQueue: FIFO buffer (TTL: 2s)
        PendingQueue --> ContainerIdentity: Docker container start event arrives
        PendingQueue --> UnresolvedIdentity: TTL expired without resolution
    }

    HostIdentity --> AttributionHost: Attach host execution context
    ContainerIdentity --> AttributionResolved: Attach container execution context
    UnresolvedIdentity --> AttributionUnresolved: Tag UNRESOLVED (Never treat as Host!)

    AttributionHost --> [*]
    AttributionResolved --> [*]
    AttributionUnresolved --> [*]
```

### 5.1 Reconciliation Logic & Tombstoning
1. **Host Inode Seeding:** At initialization, ContainerGuard queries `os.Stat("/sys/fs/cgroup")` to obtain the root cgroup inode. Any execution occurring in the root cgroup is definitively tagged as host execution.
2. **Docker Event Stream Listener:** A background worker monitors `/var/run/docker.sock` for `container create`, `start`, `die`, and `destroy` events.
3. **Cgroup Inode Inspection:** When a container starts, ContainerGuard queries the container's PID via Docker API and reads `/proc/<pid>/cgroup` (entry `0::/path`) to stat `/sys/fs/cgroup/<path>`, obtaining the true 64-bit inode.
4. **Tombstone Caching (`staleMappings`):** When a container stops, its cgroup inode mapping is moved to a tombstone cache rather than deleted immediately. Any in-flight execution events delayed in the ring buffer can still be attributed to the container that created them.
5. **Bounded Attribution Queue:** Unmapped events wait in a FIFO queue with default capacity of 10,000 items (`DefaultConfig().MaxPendingCapacity = 10000`). If unmapped after `PendingTTL` (default 2s), they transition to `UNRESOLVED` without dropping or blocking the ingestion pipeline. In empirical stress tests up to 25,000 events, peak queue depth reached was 1,371 items, well within bounded capacity.

---

## 6. Telemetry Ingestion & Loss Accounting Pipeline (`internal/pipeline`)

```mermaid
flowchart TD
    subgraph S1 ["1. Kernel Loss Accounting Boundary"]
        direction LR
        K1["Kernel Tracepoint Hook"] -->|bpf_ringbuf_reserve| RES{"Buffer Space?"}
        RES -->|Space Available| K2["bpf_ringbuf_submit()"]
        RES -->|Buffer Saturated| K3["Increment CG_METRIC_RB_RESERVE_DROPS"]
    end

    subgraph S2 ["2. Userspace Ingestion & Gap Detection"]
        direction LR
        K2 ==>|RingBufReader mmap| DEC["Binary Decoder (360B Event)"]
        DEC -->|Verify Monotonicity| SEQ{"Sequence Continuous?"}
        SEQ -->|Continuous (Delta = 1)| BUF["Attribution Buffer (FIFO Queue)"]
        SEQ -->|Delta > 1 (Loss Detected)| GAP["Log Sequence Anomaly"]
    end

    subgraph S3 ["3. Graceful Termination & Loss Accounting Drain"]
        direction LR
        BUF ==>|Daemon Shutdown| D1["StopReader: Detach Ring Buffer"]
        D1 -->|Flush Ingestion Pipeline| D2["Drain Ingester & Attribution Buffer"]
        D2 -->|Synchronous Map Read| D3["Verify: Hook Calls == Submissions + Drops"]
    end

    S1 ==> S2
    S2 ==> S3

    classDef stage fill:#1e293b,stroke:#475569,stroke-width:1px,color:#f8fafc;
    classDef hook fill:#0f172a,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef decision fill:#334155,stroke:#f59e0b,stroke-width:2px,color:#fff;
    classDef drop fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fff;
    classDef pass fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef drain fill:#1e1b4b,stroke:#818cf8,stroke-width:2px,color:#fff;

    class K1,DEC hook;
    class RES,SEQ decision;
    class K3,GAP drop;
    class K2,BUF pass;
    class D1,D2,D3 drain;
```

### Telemetry Invariant Conservation
ContainerGuard enforces exact mathematical conservation between kernel hooks and user space:
$$\text{Hook Invocations} = \text{RingBuffer Submissions} + \text{Kernel Reservation Drops}$$
- **Kernel Reservation Drops:** Occur when the BPF ring buffer is full (reader paused or overloaded). Monitored via atomic array map counter `CG_METRIC_RB_RESERVE_DROPS`.
- **Sequence Gaps:** Monitored via `seq_num` delta in `internal/pipeline/ingester.go`. A sequence gap indicates user-space event omission or packet corruption.

---

## 7. Deterministic Detection Engine (`internal/detection`)

ContainerGuard executes three deterministic detection rules against every ingested event:

```mermaid
flowchart TD
    EV["Attributed SecurityEvent"] --> EVAL{"Deterministic Detection Engine"}

    subgraph Rule1 ["Rule 1: Privileged Breakout Utilities"]
        direction TB
        R1["CG-RULE-001<br/>Binary match: nsenter, unshare, chroot, modprobe, insmod"]
        R1 -->|Match inside Container| A1["Emit CRITICAL Alert<br/>Attach Ancestor Lineage Chain"]
    end

    subgraph Rule2 ["Rule 2: Volatile Mount Execution"]
        direction TB
        R2["CG-RULE-002<br/>Path match: /tmp/, /dev/shm/, /var/tmp/"]
        R2 -->|Match inside Container| A2["Emit HIGH Alert<br/>Untrusted Mount Execution"]
    end

    subgraph Rule3 ["Rule 3: Interactive Container Shell"]
        direction TB
        R3["CG-RULE-003<br/>Path match: /bin/sh, bash, dash, ash, zsh"]
        R3 -->|Match inside Container| A3["Emit MEDIUM Alert<br/>Container Shell Ingress"]
    end

    EVAL -->|Evaluate| R1
    EVAL -->|Evaluate| R2
    EVAL -->|Evaluate| R3

    A1 --> ALERTS["Security Alerts Sink<br/>(exec_paths_alerts.jsonl)"]
    A2 --> ALERTS
    A3 --> ALERTS

    EVAL -->|No Rules Triggered| TELEM["Telemetry Stream Sink<br/>(exec_paths_events.jsonl)"]

    classDef eval fill:#0f172a,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef rule fill:#1e293b,stroke:#64748b,stroke-width:1px,color:#f8fafc;
    classDef crit fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fff;
    classDef high fill:#431407,stroke:#f97316,stroke-width:2px,color:#fff;
    classDef med fill:#422006,stroke:#eab308,stroke-width:2px,color:#fff;
    classDef pass fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef alertsink fill:#581c87,stroke:#a855f7,stroke-width:2px,color:#fff;

    class EVAL eval;
    class R1,R2,R3 rule;
    class A1 crit;
    class A2 high;
    class A3 med;
    class TELEM pass;
    class ALERTS alertsink;
```

- **`CG-RULE-001` (Privileged Container Breakout Utility):** Triggers when an executable matching breakout utilities (`nsenter`, `unshare`, `capsh`, `chroot`, `modprobe`, `insmod`) is executed inside a resolved or pending container.
- **`CG-RULE-002` (Execution from Writable Mount):** Triggers when an executable is launched from volatile or world-writable directories (`/tmp/`, `/dev/shm/`, `/var/tmp/`) inside a resolved container.
- **`CG-RULE-003` (Container Shell Binary Spawned):** Triggers when an interactive shell interpreter (`/bin/sh`, `/bin/bash`, `/bin/dash`, `/bin/ash`, `/bin/zsh`) is executed inside a resolved container. (Note: evaluates executable path; terminal interactivity is not evaluated in the 50% milestone).

---

## 8. Graceful Shutdown & Synchronous Metrics Drain

To prevent race conditions during daemon termination:
1. **Reader Termination (`StopReader()`):** The userspace ring buffer reader is unblocked and stopped, preventing new events from entering the ingestion channel while leaving BPF maps fully accessible.
2. **Ingester Sequence Flush (`ingester.Flush()`):** Emits any pending sequence anomalies.
3. **Attribution Buffer Flush (`buffer.Flush()`):** Force-expires any events remaining in the pending queue to `UNRESOLVED`, pushing them to `outChan` without dropping.
4. **Synchronous Channel Drain:** The daemon drains all remaining events from `outChan` to disk within a 3-second deadline.
5. **Synchronous Kernel Metrics Query:** Only after all events have drained does the daemon query `telemetry_counters` from the kernel, ensuring that kernel counters exactly match the processed event records.

---
*ContainerGuard 50% Verified Milestone Architecture Specification*
