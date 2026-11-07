# ContainerGuard Threat Model

## 1. Scope & System Boundaries

ContainerGuard monitors containerized workloads running on Linux hosts using cgroup v2 and Docker/containerd runtimes.

**In Scope:**
- Malicious processes spawned inside non-privileged and privileged Docker containers.
- Container escape attempts via namespace manipulation (`nsenter`, `unshare`, `capsh`).
- Execution of dropped payloads from writable container filesystems (`/tmp`, `/dev/shm`).
- Telemetry flooding attacks designed to saturate the eBPF ring buffer and induce event blindness.
- Transient lifecycle races where malicious short-lived containers execute and terminate before standard monitoring tools can attribute their identity.

**Out of Scope:**
- Hardware-level side channels (Spectre, Meltdown).
- Direct kernel exploits compromising kernel memory before eBPF tracepoint execution.
- Physical host compromise.

---

## 2. Adversarial Scenarios & Mitigation Mechanisms

| Attack Vector | Attacker Action | ContainerGuard Countermeasure |
|---|---|---|
| **Telemetry Flooding (Blind Spot Creation)** | Attacker executes high-frequency `execve` loops to fill the ring buffer and drop subsequent evasion binaries. | **Telemetry Integrity Accounting:** Kernel counters record every reservation drop; monotonic sequence gaps immediately alert security operators to missing events. |
| **Lifecycle Attribution Evasion** | Attacker starts a short-lived container, executes an exploit, and terminates within 50ms before userspace pollers inspect the container. | **Attribution State Machine & Pending Buffer:** Events are held in `PENDING` queue; Docker event streams and tombstone tables re-link execution even after container termination. |
| **PID Reuse Collisions** | Attacker causes high PID rollover to confuse process lineage trackers. | **Composite Identity Keys:** All lineage nodes are keyed by `(cgroup_id << 32) ^ TGID`, ensuring absolute isolation across containers and host restarts. |
| **Privilege Escalation / Breakout** | Attacker invokes `nsenter --mount=/proc/1/ns/mnt` to escape into host root. | **Deterministic Detection Engine (`CG-RULE-001`):** Flagged instantaneously as `CRITICAL` alert with lineage chain preserved. |
