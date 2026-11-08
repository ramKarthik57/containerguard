# ContainerGuard Technical Documentation Index

Welcome to the technical documentation repository for **ContainerGuard**, an eBPF-based runtime intrusion detection and telemetry integrity system engineered for Linux containers.

This documentation suite details the system architecture, kernel implementation, threat model, empirical evaluation, and reproducibility instructions corresponding to the **ContainerGuard 50% Verified Milestone**.

---

## 1. Core Project Specifications

- **[System Architecture (ARCHITECTURE.md)](../ARCHITECTURE.md):**  
  Comprehensive technical specification of kernel and user-space components, tracepoint interception mechanisms, BPF maps, container resolver logic, process lineage models, and telemetry lifecycle.
- **[Build & Reproduction Manual (BUILD.md)](../BUILD.md):**  
  Step-by-step instructions for compiling eBPF CO-RE bytecode, compiling the Go daemon, running test suites, executing stress and saturation benchmarks, and safely managing privilege boundaries.
- **[Threat Model & Security Design (THREAT_MODEL.md)](../THREAT_MODEL.md):**  
  Rigorous STRIDE threat analysis, trust boundaries, container breakout scenarios, detection coverage, security assumptions, and explicit non-goals.
- **[Experimental Evaluation Framework (EXPERIMENTS.md)](../EXPERIMENTS.md):**  
  Systematic scientific catalog of Experiments 1 through 5, detailing hypotheses, independent/dependent variables, measurement methodology, and empirical findings.
- **[Development Log (DEVELOPMENT_LOG.md)](../DEVELOPMENT_LOG.md):**  
  Chronological engineering record preserving project progression from initial smoke tests through Phase I adversarial validation and official GitHub release.

---

## 2. Research & Evaluation Reports

The [`docs/`](.) directory contains formal empirical evaluation reports and data audit records:

| Document | Topic & Focus Area | Key Metrics / Findings |
| :--- | :--- | :--- |
| **[50% Milestone Acceptance Report](MILESTONE_50_PERCENT_ACCEPTANCE_REPORT.md)** | Official milestone verification across all 16 foundational components | All 16 components accepted; frozen at commit `b8f70f5` |
| **[Technical Audit Report](TECHNICAL_AUDIT_REPORT.md)** | End-to-end system audit across telemetry, attribution, lineage, and rules | Mathematical conservation verification, shutdown synchronization audit |
| **[Stress Test Results](STRESS_TEST_RESULTS.md)** | Workload scaling across 4 execution tiers (1,000 to 25,000 events) | Zero sequence gaps, 100.00% delivery up to 1,923 events/sec |
| **[Saturation & Backpressure Evaluation](SATURATION_EVALUATION.md)** | Capacity bounds and deliberate reader backpressure under memory constraints | Verified exact conservation: $\text{Hooks} = \text{Submits} + \text{Drops}$ |
| **[Phase I Adversarial Evaluation](PHASE_I_ADVERSARIAL_EVALUATION.md)** | Multi-tracepoint execution-path coverage and adversarial resilience | 14 execution pathways verified (`execve`, `execveat`, `memfd`, symlinks) |
| **[Execution-Path Coverage Analysis](EXECUTION_PATH_COVERAGE.md)** | Live kernel validation of committed vs. failed executions | Differentiation of `sched_process_exec` vs. `sys_exit_execve` errno |
| **[Detection Engine Validation](DETECTION_VALIDATION.md)** | Evaluation of rules `CG-RULE-001`, `002`, `003` against labelled corpus | 100% Precision, 100% Recall on labelled benchmark suite |
| **[Overhead Benchmarking Report](OVERHEAD_EVALUATION.md)** | Amortized execution latency, CPU footprint, and RSS memory usage | Descriptive mean overhead: 4.71% ($10.22\ \mu\text{s}$ wall-clock delta) |
| **[GitHub Publication Report](GITHUB_PUBLICATION_REPORT.md)** | Record of initial GitHub repository creation, tag, and asset publication | Private repository initialized at `ramKarthik57/containerguard` |
| **[Experiment Provenance Manifest](EXPERIMENT_PROVENANCE_MANIFEST.md)** | Reproducibility manifest: source commits, binary digests, commands, and evidence paths | End-to-end provenance mapping across Experiments 1–5 |

---

## 3. Empirical Evidence Archives

Raw telemetry streams, JSONL alert logs, and benchmark profiling outputs are preserved under [`docs/evidence/`](evidence/):
- **[`evidence/phase_f/`](evidence/phase_f/):** Preliminary baseline integration runs and cgroup resolution logs.
- **[`evidence/phase_h/`](evidence/phase_h/):** Scaled stress test runs across 1,000, 5,000, 10,000, and 25,000 events.
- **[`evidence/phase_h2/`](evidence/phase_h2/):** Controlled buffer capacity and reader backpressure evaluation datasets (including `original_unreconciled/` records).
- **[`evidence/phase_i/`](evidence/phase_i/):** Adversarial execution path event streams, detection confusion matrix inputs, and overhead benchmark reports.

---

## 4. Glossary of Core Concepts

- **BPF Ring Buffer (`events`):** High-throughput, multi-producer, single-consumer memory-mapped ring buffer used to transfer 360-byte binary telemetry records from kernel space to user space (occupying 368 bytes on the wire including the 8-byte kernel record header).
- **ProcessInstanceKey (`{TGID, StartTimeNS}`):** Immutable process identity construct that uniquely identifies a process lifecycle across PID recycling, cgroup migrations, and container boundaries.
- **Cgroup Inode:** 64-bit filesystem inode of a cgroup v2 directory (retrieved via `BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id)`), serving as the immutable kernel handle for container attribution.
- **Committed Execution:** A successful execution finalized at the `sched_process_exec` tracepoint after kernel binary loaders have succeeded, flagged with `CG_FLAG_COMMITTED_EXEC`.
- **Failed Execution:** An execution attempt that failed in the kernel (e.g., `ENOENT`, `EACCES`), intercepted at `sys_exit_execve` or `sys_exit_execveat` with `CG_FLAG_EXEC_FAILED` and negative exit code.
- **Telemetry Conservation Equation:** The strict mathematical invariant enforced across all evaluations:  
  $$\text{Kernel Hook Invocations} = \text{RingBuffer Submissions} + \text{Kernel Reservation Drops}$$

---
*ContainerGuard 50% Verified Milestone Documentation Index*
