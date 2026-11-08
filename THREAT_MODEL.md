# ContainerGuard Threat Model & Security Engineering Specification

**Release Milestone:** ContainerGuard 50% Verified Milestone  
**Scope:** Linux Container Runtime Observability & Kernel Telemetry Integrity  
**Applicable Architecture:** Linux Kernel 6.x+, cgroup v2, Docker/containerd runtimes

---

## 1. Executive Summary & Security Objectives

ContainerGuard operates as an autonomous kernel-level intrusion detection and telemetry verification system. Its primary security objective is to provide **unforgeable, loss-aware execution visibility** across Linux container environments, ensuring that adversaries cannot silently execute arbitrary code, manipulate container namespaces, or blind security operators through telemetry exhaustion.

### Primary Security Objectives:
1. **Unambiguous Workload Attribution:** Reliably bind every kernel execution event to its originating container runtime identity.
2. **Telemetry Loss Awareness:** Prevent silent event dropping; if telemetry loss occurs due to resource saturation, it must be explicitly accounted for, quantified, and surfaced.
3. **Execution Semantics Fidelity:** Accurately distinguish execution attempts, committed binaries, and kernel-side execution failures across all Linux execution entry points (`execve` and `execveat`).
4. **Resilience to Transient Lifecycle Manipulation:** Preserve process lineage and container attribution across rapid container destruction, renaming, PID recycling, and cgroup migrations.

---

## 2. Trust Boundaries & System Architecture Boundaries

The ContainerGuard security architecture defines four distinct trust domains:

```mermaid
flowchart TD
    subgraph TD1 ["Trust Domain 1: Untrusted Container Workloads (L1)"]
        C1["Unprivileged Container Processes"]
        C2["Compromised Privileged Containers"]
        C3["Malicious Entrypoints & Injected Binaries"]
    end

    subgraph TD2 ["Trust Domain 2: Container Runtime & Host User Space (L2)"]
        DOCK["Docker Engine / containerd-shim"]
        CGROUP["cgroup v2 Filesystem Hierarchy"]
        PROC["/proc Filesystem"]
    end

    subgraph TD3 ["Trust Domain 3: ContainerGuard Control Plane (L3)"]
        DAEMON["ContainerGuard Daemon (Go)"]
        LINEAGE["Lineage Tracker & Ingestion Pipeline"]
        DETECTION["Deterministic Detection Engine"]
        STORAGE["Local JSONL Storage"]
    end

    subgraph TD4 ["Trust Domain 4: Trusted Linux Kernel (L4)"]
        TRACE["Kernel Tracepoint Hooks"]
        EBPF["ContainerGuard eBPF Programs (CO-RE)"]
        MAPS["BPF Ring Buffer & Atomic Counters"]
    end

    TD1 -->|Syscall Boundary (execve/execveat)| TD4
    TD4 -->|mmap Boundary (BPF Ring Buffer)| TD3
    TD2 -->|Docker Unix Socket & cgroup Inodes| TD3
    TD3 -->|Alerts & Telemetry Stream| STORAGE

    classDef td1 fill:#7f1d1d,stroke:#f87171,stroke-width:2px,color:#fff;
    classDef td2 fill:#78350f,stroke:#fbbf24,stroke-width:2px,color:#fff;
    classDef td3 fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#fff;
    classDef td4 fill:#1e1b4b,stroke:#818cf8,stroke-width:2px,color:#fff;
    class C1,C2,C3 td1;
    class DOCK,CGROUP,PROC td2;
    class DAEMON,LINEAGE,DETECTION,STORAGE td3;
    class TRACE,EBPF,MAPS td4;
```

### Trust Domain Analysis:
- **Trust Domain 1 (Untrusted Workload):** Assumed to be potentially hostile. Attackers may have arbitrary root inside the container, mount namespaces, or execute exploit payloads from `/tmp`.
- **Trust Domain 2 (Host User Space & Runtimes):** Semi-trusted. Docker daemon and containerd execute on the host, but may lag in event notification or experience race conditions during rapid container shutdown.
- **Trust Domain 3 (ContainerGuard Control Plane):** Trusted user-space daemon executing with administrative capabilities (`CAP_BPF`, `CAP_SYS_ADMIN`). Responsible for ingestion, decoding, and attribution.
- **Trust Domain 4 (Linux Kernel & eBPF):** Root of trust. Kernel memory, BPF bytecode execution, and atomic hardware counters are trusted.

---

## 3. Threat Actor Profiles & Adversarial Capabilities

| Threat Actor | Capabilities & Access | Objective |
| :--- | :--- | :--- |
| **Container Breakout Attacker** | Root privileges inside container (`CAP_SYS_ADMIN` in container namespace or privileged container flag). | Escape container isolation to host filesystem or host namespace via `nsenter`, `unshare`, or cgroup manipulation. |
| **Evasive Malware / Dropper** | Code execution inside container; memory execution capabilities (`memfd_create`), temporary mounts (`/dev/shm`). | Drop second-stage payloads into writable mounts, execute via symlinks or anonymous descriptors to evade file integrity monitoring. |
| **Telemetry Denial-of-Service Attacker** | Ability to spawn thousands of short-lived processes or recursive `execve` loops inside a container. | Overwhelm the eBPF ring buffer, forcing reservation drops to conceal subsequent malicious payloads within the dropped event burst. |
| **Lifecycle Anti-Forensics Attacker** | Ephemeral container execution; ability to spin up containers, execute rapid attacks, and destroy containers within milliseconds. | Evade user-space monitoring agents that rely on periodic polling of `/proc` or Docker API state. |

---

## 4. STRIDE Threat Analysis Matrix

| Threat Category | Target Subsystem | Adversarial Attack Vector | ContainerGuard Countermeasure & Architecture Defense |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Process Lineage & PID Identity | Attacker generates high PID churn to recycle a PID, claiming false parentage from a trusted system process. | **`ProcessInstanceKey{TGID, StartTimeNS}`:** Lineage tracking is keyed on monotonic process start time, making PID recycling collisions mathematically impossible. |
| **Tampering** | Process Metadata & Comm Names | Attacker invokes `prctl(PR_SET_NAME)` to disguise a malicious binary as a benign daemon (e.g. `systemd` or `dockerd`). | **Post-Exec Tracepoint Sampling:** Binary command names are captured directly at `sched_process_exec` after binary loading. Paths are extracted from kernel `dentry`. |
| **Repudiation** | Telemetry Loss / Event Omission | Attacker floods the system with executions to induce kernel ring buffer drops, claiming an attack did not occur. | **Dual Loss Accounting & Invariant Verification:** Kernel atomic counter `CG_METRIC_RB_RESERVE_DROPS` records every failure. $\text{Hooks} = \text{Submissions} + \text{Drops}$ exposes all loss. |
| **Information Disclosure** | Memory-mapped Ring Buffer | Unprivileged host user attempts to read BPF ring buffer to snoop container execution telemetry. | **Kernel Access Controls:** BPF maps are accessible only by `root` / `CAP_BPF`. Ring buffer memory is mapped with restricted permissions (`0600`). |
| **Denial of Service** | BPF Ring Buffer & Userspace Queue | Rapid execution burst saturates kernel ring buffer and fills user-space attribution buffer queues. | **Bounded Attribution Queues:** Ingestion queue is strictly bounded (default 10,000 items per `DefaultConfig().MaxPendingCapacity`) with TTL-based expiration (`PendingTTL`), preventing daemon OOM. |
| **Elevation of Privilege** | Container Boundary / Host Namespace | Attacker executes privileged utility (`nsenter`, `chroot`, `modprobe`) or setuid binary to transition to host EUID 0. | **`CG-RULE-001` & `CG_FLAG_SETUID_EXEC`:** In-kernel credential check (`cur_task->cred->euid.val != uid`) flags setuid escalation; rule engine emits `CRITICAL` alerts. |

---

## 5. Detailed Attack Scenarios & Mitigations

### 5.1 Scenario A: Namespace Breakout via Utility Invocation
- **Attack Vector:** An adversary gains root inside a misconfigured container (`--privileged` or `CAP_SYS_ADMIN`) and executes `nsenter --target 1 --mount --uts --ipc --net --pid /bin/sh` to pivot into the host root namespace.
- **ContainerGuard Defense:**
  1. The execution is intercepted at `sys_enter_execve` and committed at `sched_process_exec`.
  2. The cgroup v2 inode maps the execution to the container runtime context (`AttributionResolved`).
  3. `CG-RULE-001` (`ContainerEscapeRule`) triggers immediately on `/usr/bin/nsenter`, extracting the full parentage chain from `LineageTracker` and emitting a `CRITICAL` alert with container metadata.

### 5.2 Scenario B: Anonymous Execution via In-Memory File Descriptor (`memfd`)
- **Attack Vector:** An attacker avoids writing binaries to disk by creating an anonymous memory file descriptor via `memfd_create()`, writing an ELF payload into it, and invoking `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`.
- **ContainerGuard Defense:**
  1. Standard tools monitoring only `sys_enter_execve` miss this entirely. ContainerGuard intercepts `tracepoint/syscalls/sys_enter_execveat`.
  2. The `AT_EMPTY_PATH` flag (`0x1000`) is detected and recorded in `event.flags` as `CG_FLAG_AT_EMPTY_PATH`.
  3. At `sched_process_exec`, ContainerGuard falls back to the kernel-resolved binary path from `trace_event_raw_sched_process_exec.__data_loc_filename`, capturing `/memfd:...` execution and defeating filesystem evasion.

### 5.3 Scenario C: Telemetry Flooding & Ring Buffer Exhaustion
- **Attack Vector:** The adversary spawns an execution fork-bomb inside a container (e.g. 10,000 rapid executions), hoping to fill the kernel ring buffer so that an exploit binary launched immediately afterwards is dropped unobserved.
- **ContainerGuard Defense:**
  1. Every attempt increments `CG_METRIC_HOOK_CALLS`.
  2. When the 16 MiB ring buffer fills, `bpf_ringbuf_reserve()` returns NULL.
  3. The kernel increments `CG_METRIC_RB_RESERVE_DROPS` atomically.
  4. Telemetry integrity accounting in user space immediately flags the loss condition:
     $$\text{Delivery Rate} = \frac{\text{Decoded}}{\text{Submissions} + \text{Drops}} < 100\%$$
  5. The security operator is immediately notified of deliberate telemetry loss and event suppression.

### 5.4 Scenario D: Rapid Container Spin-Up and Destruction Race
- **Attack Vector:** The attacker scripts a container to start, execute an exploit against a local service, and terminate within 50 milliseconds, before periodic `/proc` pollers can detect the container ID.
- **ContainerGuard Defense:**
  1. The kernel captures the execution immediately at startup with the container's cgroup inode.
  2. If the Docker event has not yet reached user space, the event is held in `AttributionBuffer` in a `PENDING` state.
  3. When Docker emits the `start` event, the cgroup inode is reconciled and the event transitions to `RESOLVED`.
  4. Even if the container dies before reconciliation, `staleMappings` tombstoning retains the mapping, ensuring post-mortem attribution.

---

## 6. Assumptions & Non-Goals

### Security Assumptions:
1. **Kernel Integrity:** The underlying Linux kernel is assumed not to have suffered pre-existing arbitrary kernel memory corruption before ContainerGuard attaches its eBPF tracepoints.
2. **Container Runtime Integrity:** The host Docker daemon Unix socket (`/var/run/docker.sock`) is assumed to be accessible only by trusted host administrators.
3. **Hardware Trust:** Hardware execution, CPU registers, and memory controllers operate correctly without active Spectre/Meltdown side-channel compromises.

### Explicit Non-Goals (Out of Scope for 50% Milestone):
- **Synchronous In-Kernel Blocking (LSM Prevention):** ContainerGuard is currently an *intrusion detection* and *telemetry verification* system, not an inline prevention system. Tracepoints observe events asynchronously; they do not return `-EPERM` to abort syscalls.
- **Network Packet Payload Inspection:** ContainerGuard focuses exclusively on execution telemetry, process lineage, and container boundary monitoring. Raw network socket contents are not monitored.
- **Arbitrary Rootkit Defense:** A threat actor with arbitrary kernel write privileges (e.g., via compromised signed kernel modules) could disable eBPF programs. Defending against direct kernel rootkits is outside the research scope.

---
*ContainerGuard 50% Verified Milestone Threat Model*
