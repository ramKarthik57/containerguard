# Detection Engine Validation & False-Positive Evaluation Report

**Release Milestone:** ContainerGuard 50% Verified Milestone  
**Rules Evaluated:** `CG-RULE-001`, `CG-RULE-002`, `CG-RULE-003`  
**Test Script:** `scripts/detection_benchmark.sh`  
**Evidence Artifacts:**
- Initial Evaluation (Commit `7c56b1e`): 133 events (`evidence/phase_i/detection_events.jsonl` at `7c56b1e`)
- Milestone Rerun (Commit `b8f70f5`): 132 events ([`evidence/phase_i/detection_validation_report.json`](evidence/phase_i/detection_validation_report.json), [`evidence/phase_i/detection_alerts.jsonl`](evidence/phase_i/detection_alerts.jsonl))

---

## 1. Methodology & Corpus Construction

To evaluate detection fidelity, specificity, and false-positive rates (FPR), ContainerGuard was evaluated against a mixed workload corpus containing both benign developer workflows and synthetic attack simulations.

### Workload Composition:
1. **Benign Developer Workload (120 Scripted Events):**
   - **Git Operations (6 operations):** Repository initialization (`git init`), staging (`git add`), committing (`git commit`), diffing (`git diff`), branch status (`git status`), history traversal (`git log`).
   - **Build Toolchains:** Multi-stage GCC compilation (`gcc -c`, `gcc -o`), intermediate assembler/compiler stages (`cc1`, `as`, `collect2`), and test binary execution.
   - **System Utilities:** Routine file manipulation and container queries (`ls -la`, `cat`, `uptime`, `date`, `uname -a`).
   - **Cross-Host Validation:** Host commands executing utilities that would be suspicious inside containers (e.g., host `sudo` or host package inspection), verifying container isolation.
2. **Controlled Attack Simulations (12 Scripted Events):**
   - **`CG-RULE-001` (Breakout Utilities):** Containerized execution of `nsenter`, `unshare`, `chroot`, and `modprobe`.
   - **`CG-RULE-002` (Writable Directory Execution):** Binaries executed from container writable mounts `/tmp/bad_tmp_exec` and `/var/tmp/bad_var_exec`.
   - **`CG-RULE-003` (Container Shell Binaries):** Shell interpreters (`/bin/sh`, `/bin/bash`) spawned inside monitored containers.

---

## 2. Dataset Reconciliation: Initial Evaluation (133 Events) vs. Milestone Rerun (132 Events)

The evaluation was performed across two distinct runs, preserved in Git history:

| Dataset | Commit Checkpoint | Scripted Operations | Ambient Host Events | Total Unique Events | Total Rule-Event Decisions |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Dataset 1 (Initial Evaluation)** | `7c56b1e` | 132 (120 benign + 12 attack) | 1 (`/usr/bin/git`, PPID 1016) | **133** | **399** ($3 \times 133$) |
| **Dataset 2 (Milestone Rerun)** | `b8f70f5` | 132 (120 benign + 12 attack) | 0 | **132** | **396** ($3 \times 132$) |

### Forensic Identification of the Ambient Host Event (Dataset 1)
In Dataset 1, a single extra event was captured during the daemon shutdown drain:
```json
{
  "captured_at": "2026-11-08T06:46:02.887Z",
  "kernel_time_ns": 22439016501211,
  "seq_num": 130,
  "cgroup_id": 22,
  "tid": 16615,
  "tgid": 16615,
  "parent_tgid": 1016,
  "comm": "git",
  "filename": "/usr/bin/git",
  "attribution_state": "UNRESOLVED"
}
```
- **Process Lineage & Context:** Parent process (`ParentTGID: 1016`, `StartTimeNS: 17478663146`, comm `language_server`) represents background IDE workspace polling in the WSL2 host environment.
- **Classification & Attribution Distinction:**
  - **Manual Benchmark Ground Truth:** Benign ambient IDE-associated activity executing in the host environment.
  - **ContainerGuard Telemetry Attribution:** Left strictly as `UNRESOLVED` (`attribution_state: "UNRESOLVED"`), because cgroup 22 did not match any active container in Docker's inventory or the seeded host root cgroup.
  - **Fail-Safe Behavior in Action:** Rather than defaulting unknown cgroups to host authority, ContainerGuard preserved the `UNRESOLVED` classification. Because `/usr/bin/git` matches no container breakout patterns (`CG-RULE-001`), is not in volatile writable mounts (`CG-RULE-002`), and is not a container shell interpreter (`CG-RULE-003`), no alert was generated. With respect to the container attack evaluation ground truth, this benign background execution was correctly scored as a True Negative (+1 TN across each rule), preserving 100% precision and 0 false positives.
- **Milestone Rerun (Dataset 2):** Daemon shutdown synchronized immediately prior to the language server's next polling interval, resulting in exactly the 132 scripted operations.

---

## 3. Results by Rule

### 3.1 `CG-RULE-001`: Privileged Breakout Utilities
- **Description:** Detects containerized execution of utilities commonly employed in namespace escape exploits (`nsenter`, `unshare`, `capsh`, `chroot`, `modprobe`, `insmod`).
- **Attribution Guard:** Must be in state `RESOLVED` or `PENDING` (attributed to a container). Host executions are ignored.
- **Dataset 1 (133 Events):** $\text{TP} = 4, \text{FP} = 0, \text{TN} = 129, \text{FN} = 0$
- **Dataset 2 (132 Events):** $\text{TP} = 4, \text{FP} = 0, \text{TN} = 128, \text{FN} = 0$
- **Metrics (Both Runs):** Precision = $100.00\%$, Recall = $100.00\%$, Specificity = $100.00\%$, FPR = **0.00%**.

### 3.2 `CG-RULE-002`: Writable Directory Execution
- **Description:** Detects execution of binaries residing in writable or temporary filesystems inside containers (`/tmp/`, `/dev/shm/`, `/var/tmp/`).
- **Attribution Guard:** Only fires on resolved container workloads (`AttributionResolved`).
- **Dataset 1 (133 Events):** $\text{TP} = 3, \text{FP} = 0, \text{TN} = 130, \text{FN} = 0$
- **Dataset 2 (132 Events):** $\text{TP} = 3, \text{FP} = 0, \text{TN} = 129, \text{FN} = 0$
- **Metrics (Both Runs):** Precision = $100.00\%$, Recall = $100.00\%$, Specificity = $100.00\%$, FPR = **0.00%**.

### 3.3 `CG-RULE-003`: Shell Binary Executed Inside Container
- **Description:** Detects execution of shell interpreter binaries (`/bin/sh`, `/bin/bash`, `/bin/dash`, `/bin/ash`, `/bin/zsh`) within monitored containers.
- **Attribution Guard:** Only fires on resolved container workloads (`AttributionResolved`).
- **Scope Qualification:** Intercepts binary path execution. **Terminal interactivity (pty/tty allocation or `-i` flags) is not evaluated.**
- **Dataset 1 (133 Events):** $\text{TP} = 5, \text{FP} = 0, \text{TN} = 128, \text{FN} = 0$
- **Dataset 2 (132 Events):** $\text{TP} = 5, \text{FP} = 0, \text{TN} = 127, \text{FN} = 0$
- **Metrics (Both Runs):** Precision = $100.00\%$, Recall = $100.00\%$, Specificity = $100.00\%$, FPR = **0.00%**.

---

## 4. Confusion Matrix Comparison Tables

### Dataset 1: Initial Evaluation (Commit `7c56b1e`, 133 Unique Events, 399 Rule Decisions)
| Rule ID | Rule Definition | TP | FP | TN | FN | Precision | Recall | FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`CG-RULE-001`** | Breakout Utilities | 4 | 0 | 129 | 0 | 100.00% | 100.00% | 0.00% |
| **`CG-RULE-002`** | Writable Mount Exec | 3 | 0 | 130 | 0 | 100.00% | 100.00% | 0.00% |
| **`CG-RULE-003`** | Container Shell Binary | 5 | 0 | 128 | 0 | 100.00% | 100.00% | 0.00% |
| **Macro Average** | **Across All 3 Rules** | **12** | **0** | **387** | **0** | **100.00%** | **100.00%** | **0.00%** |

### Dataset 2: Milestone Rerun (Commit `b8f70f5`, 132 Unique Events, 396 Rule Decisions)
| Rule ID | Rule Definition | TP | FP | TN | FN | Precision | Recall | FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`CG-RULE-001`** | Breakout Utilities | 4 | 0 | 128 | 0 | 100.00% | 100.00% | 0.00% |
| **`CG-RULE-002`** | Writable Mount Exec | 3 | 0 | 129 | 0 | 100.00% | 100.00% | 0.00% |
| **`CG-RULE-003`** | Container Shell Binary | 5 | 0 | 127 | 0 | 100.00% | 100.00% | 0.00% |
| **Macro Average** | **Across All 3 Rules** | **12** | **0** | **384** | **0** | **100.00%** | **100.00%** | **0.00%** |

---

## 5. Scope Boundary & Research Limitations

> [!IMPORTANT]
> The reported detection metrics ($100.00\%$ Precision, $100.00\%$ Recall, $0.00\%$ FPR) apply **strictly to the empirical labelled benchmark test suite**. ContainerGuard does not claim universal production detection accuracy, zero false positives across unconstrained production environments, or immunity to adversarial evasion.
