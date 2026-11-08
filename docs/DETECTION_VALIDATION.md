# Detection Engine Validation & False-Positive Evaluation Report

**Phase:** Phase I.4  
**Date:** 2026-11-08  
**Rules Evaluated:** `CG-RULE-001`, `CG-RULE-002`, `CG-RULE-003`  
**Evidence Artifact:** `docs/evidence/phase_i/detection_validation_report.json`  
**Alerts Log:** `docs/evidence/phase_i/detection_alerts.jsonl`  

---

## 1. Methodology & Corpus Construction

To evaluate detection fidelity, specificity, and false-positive rates (FPR), ContainerGuard was evaluated against an interleaved workload corpus comprising:
1. **Benign Developer Corpus (121 events):**
   - **Git Operations:** Repository initialization (`git init`), staging (`git add`), committing (`git commit`), diffing (`git diff`), branch status (`git status`), history traversal (`git log`).
   - **Build Toolchains:** Multi-stage GCC compilation (`gcc -c`, `gcc -o`), object linking, and test binary execution.
   - **System Utilities:** Routine file manipulation and container queries (`ls -la`, `cat`, `uptime`, `date`, `uname -a`).
   - **Cross-Host Validation:** Host commands executing utilities that would be suspicious inside containers (e.g., host `sudo` or host package inspection), verifying container isolation.
2. **Controlled Attack Simulations (12 events):**
   - **CG-RULE-001 (Breakout Utilities):** Containerized execution of `nsenter`, `unshare`, `chroot`, and `modprobe`.
   - **CG-RULE-002 (Writable Directory Execution):** Binaries executed from container writable mounts `/tmp/`, `/dev/shm/`, and `/var/tmp/`.
   - **CG-RULE-003 (Interactive Container Shells):** Shell binaries (`/bin/sh`) spawned inside production containers.

---

## 2. Empirical Confusion Matrix & Metric Definitions

### 2.1 Metric Formulae
- **True Positives (TP):** Attack events correctly flagged by the rule.
- **False Positives (FP):** Benign developer events incorrectly flagged by the rule.
- **True Negatives (TN):** Benign developer events correctly ignored by the rule.
- **False Negatives (FN):** Attack events missed by the rule.
- **Precision:** $\frac{\text{TP}}{\text{TP} + \text{FP}}$
- **Recall (Sensitivity):** $\frac{\text{TP}}{\text{TP} + \text{FN}}$
- **Specificity:** $\frac{\text{TN}}{\text{TN} + \text{FP}}$
- **False Positive Rate (FPR):** $\frac{\text{FP}}{\text{FP} + \text{TN}} = 1 - \text{Specificity}$

---

## 3. Results by Rule

### 3.1 CG-RULE-001: Privileged Breakout Utilities
- **Description:** Detects containerized execution of utilities commonly employed in namespace escape exploits (`nsenter`, `unshare`, `capsh`, `chroot`, `modprobe`, `insmod`).
- **Attribution Guard:** Must be in state `RESOLVED` or `PENDING` (attributed to a container). Host executions are ignored.
- **Confusion Matrix:**
  $$\text{TP} = 4, \quad \text{FP} = 0, \quad \text{TN} = 129, \quad \text{FN} = 0$$
- **Metrics:**
  - **Precision:** $100.00\%$
  - **Recall:** $100.00\%$
  - **Specificity:** $100.00\%$
  - **False Positive Rate (FPR):** **0.00%**

### 3.2 CG-RULE-002: Writable Directory Execution
- **Description:** Detects execution of binaries residing in writable or temporary filesystems inside containers (`/tmp/`, `/dev/shm/`, `/var/tmp/`).
- **Attribution Guard:** Only fires on resolved container workloads (`AttributionResolved`).
- **Confusion Matrix:**
  $$\text{TP} = 3, \quad \text{FP} = 0, \quad \text{TN} = 130, \quad \text{FN} = 0$$
- **Metrics:**
  - **Precision:** $100.00\%$
  - **Recall:** $100.00\%$
  - **Specificity:** $100.00\%$
  - **False Positive Rate (FPR):** **0.00%**

### 3.3 CG-RULE-003: Interactive Shell Spawned in Container
- **Description:** Detects invocation of interactive shells (`/bin/sh`, `/bin/bash`, `/bin/dash`, `/bin/ash`, `/bin/zsh`) within monitored containers.
- **Attribution Guard:** Only fires on resolved container workloads (`AttributionResolved`).
- **Confusion Matrix:**
  $$\text{TP} = 5, \quad \text{FP} = 0, \quad \text{TN} = 128, \quad \text{FN} = 0$$
- **Metrics:**
  - **Precision:** $100.00\%$
  - **Recall:** $100.00\%$
  - **Specificity:** $100.00\%$
  - **False Positive Rate (FPR):** **0.00%**

---

## 4. Overall Detection Performance Summary

| Rule ID | Rule Focus | Evaluated Workload | TP | FP | TN | FN | Precision | Recall | FPR |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CG-RULE-001** | Breakout Utilities | 133 events | 4 | 0 | 129 | 0 | 100.00% | 100.00% | **0.00%** |
| **CG-RULE-002** | Writable Mount Exec | 133 events | 3 | 0 | 130 | 0 | 100.00% | 100.00% | **0.00%** |
| **CG-RULE-003** | Container Shell | 133 events | 5 | 0 | 128 | 0 | 100.00% | 100.00% | **0.00%** |
| **Aggregate** | **All Rules** | **133 events** | **12** | **0** | **387** | **0** | **100.00%** | **100.00%** | **0.00%** |

### Key Findings
1. **Zero False Positives Across Developer Activities:** Intensive Git operations (6 commands) and GCC compilation toolchains (invoking compiler preprocessors, assembler, and linker) generated zero spurious alerts because they occurred in host execution context.
2. **Deterministic Attribution Filter:** Ground truth separation between host and container workloads prevented host breakout utility tests from triggering container escape alerts.
3. **Lineage Context Enrichment:** Every generated alert contained complete reconstructed process lineage from the in-memory lineage tracker, identifying the parent process and start timestamp.
