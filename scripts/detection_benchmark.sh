#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EVIDENCE_DIR="${ROOT_DIR}/docs/evidence/phase_i"

mkdir -p "${EVIDENCE_DIR}"

EVENTS_LOG="${EVIDENCE_DIR}/detection_events.jsonl"
ALERTS_LOG="${EVIDENCE_DIR}/detection_alerts.jsonl"
DAEMON_LOG="${EVIDENCE_DIR}/detection_daemon.log"
REPORT_JSON="${EVIDENCE_DIR}/detection_validation_report.json"

rm -f "${EVENTS_LOG}" "${ALERTS_LOG}" "${DAEMON_LOG}" "${REPORT_JSON}"

echo "================================================================="
echo " ContainerGuard Phase I: Detection Validation & False-Positive Evaluation"
echo "================================================================="

# 1. Start ContainerGuard daemon
echo "[1/5] Starting ContainerGuard daemon..."
sudo "${ROOT_DIR}/bin/containerguard" \
    -bpf "${ROOT_DIR}/bpf/execve_events.o" \
    -events-log "${EVENTS_LOG}" \
    -alerts-log "${ALERTS_LOG}" \
    -metrics-interval 1s > "${DAEMON_LOG}" 2>&1 &
DAEMON_PID=$!
echo "[+] ContainerGuard active with PID ${DAEMON_PID}"
sleep 1.0

# 2. Run Benign Developer Workload Corpus
echo "[2/5] Dispatching Benign Developer Workload Corpus..."

# A. Benign host development operations: Git lifecycle
BENIGN_GIT_DIR="/tmp/cg_benign_git_repo"
rm -rf "${BENIGN_GIT_DIR}"
mkdir -p "${BENIGN_GIT_DIR}"
(
    cd "${BENIGN_GIT_DIR}"
    git init -q
    git config user.name "Benign Tester"
    git config user.email "tester@example.com"
    echo "hello" > file1.txt
    git add file1.txt
    git commit -m "initial commit" -q
    echo "world" >> file1.txt
    git diff > /dev/null
    git status -s > /dev/null
    git log -n 1 > /dev/null
)
rm -rf "${BENIGN_GIT_DIR}"

# B. Benign host compilation: GCC multi-step build
BENIGN_BUILD_DIR="/tmp/cg_benign_build"
mkdir -p "${BENIGN_BUILD_DIR}"
cat << 'EOF' > "${BENIGN_BUILD_DIR}/calc.c"
#include <stdio.h>
int add(int a, int b) { return a + b; }
int main() { printf("result: %d\n", add(3, 4)); return 0; }
EOF
(
    cd "${BENIGN_BUILD_DIR}"
    gcc -c calc.c -o calc.o
    gcc calc.o -o calc_bin
    ./calc_bin > /dev/null
)
rm -rf "${BENIGN_BUILD_DIR}"

# C. Benign container workloads: routine diagnostics
echo "  -> Running benign container queries..."
sudo docker exec cg-test-a /bin/date > /dev/null
sudo docker exec cg-test-a /bin/ls -la /etc > /dev/null
sudo docker exec cg-test-a /bin/uname -a > /dev/null
sudo docker exec cg-test-a /bin/uptime > /dev/null
sudo docker exec cg-test-b-event-test /bin/date > /dev/null
sudo docker exec cg-test-b-event-test /bin/ls /bin > /dev/null

sleep 1.0

# 3. Run Controlled Attack Simulation Suite
echo "[3/5] Dispatching Attack Simulation Suite..."

# Rule CG-RULE-001: Container Escape Utilities
echo "  -> Simulating CG-RULE-001 (Breakout utilities: nsenter, unshare, chroot, modprobe)..."
sudo docker exec cg-test-a /bin/nsenter --help > /dev/null 2>&1 || true
sudo docker exec cg-test-a /bin/unshare --help > /dev/null 2>&1 || true
sudo docker exec cg-test-a /bin/chroot / /bin/true > /dev/null 2>&1 || true
sudo docker exec cg-test-a /bin/modprobe --help > /dev/null 2>&1 || true

# Rule CG-RULE-002: Writable Directory Executions
echo "  -> Simulating CG-RULE-002 (Writable directory executions: /tmp, /dev/shm, /var/tmp)..."
sudo docker exec cg-test-a sh -c 'cp /bin/true /tmp/bad_tmp_exec && /tmp/bad_tmp_exec && rm -f /tmp/bad_tmp_exec' || true
sudo docker exec cg-test-a sh -c 'cp /bin/true /dev/shm/bad_shm_exec && /dev/shm/bad_shm_exec && rm -f /dev/shm/bad_shm_exec' || true
sudo docker exec cg-test-a sh -c 'mkdir -p /var/tmp && cp /bin/true /var/tmp/bad_var_exec && /var/tmp/bad_var_exec && rm -f /var/tmp/bad_var_exec' || true

# Rule CG-RULE-003: Shell Spawned in Container
echo "  -> Simulating CG-RULE-003 (Interactive shells in container)..."
sudo docker exec cg-test-a /bin/sh -c 'exit 0' || true
sudo docker exec cg-test-b-event-test /bin/sh -c 'exit 0' || true

sleep 1.0

# 4. Shut down ContainerGuard daemon
echo "[4/5] Shutting down ContainerGuard daemon..."
sudo kill -TERM "${DAEMON_PID}" || true
wait "${DAEMON_PID}" 2>/dev/null || true
echo "[+] ContainerGuard stopped gracefully."

# 5. Compile Empirical Evaluation and Confusion Matrix
echo "[5/5] Compiling Detection & False-Positive Evaluation..."

python3 - << 'PYEOF'
import json
import os

evidence_dir = "docs/evidence/phase_i"
events_log = os.path.join(evidence_dir, "detection_events.jsonl")
alerts_log = os.path.join(evidence_dir, "detection_alerts.jsonl")
report_path = os.path.join(evidence_dir, "detection_validation_report.json")

events = []
if os.path.exists(events_log):
    with open(events_log, "r") as f:
        for line in f:
            if line.strip():
                try:
                    events.append(json.loads(line.strip()))
                except Exception:
                    pass

alerts = []
if os.path.exists(alerts_log):
    with open(alerts_log, "r") as f:
        for line in f:
            if line.strip():
                try:
                    alerts.append(json.loads(line.strip()))
                except Exception:
                    pass

# Categorize events into Benign vs Attack Ground Truth
# Ground truth definition:
# CG-RULE-001 ground truth: containerized events executing nsenter, unshare, chroot, modprobe
# CG-RULE-002 ground truth: containerized events executing from /tmp/, /dev/shm/, /var/tmp/
# CG-RULE-003 ground truth: containerized events executing /bin/sh, /bin/bash, etc.

rules = ["CG-RULE-001", "CG-RULE-002", "CG-RULE-003"]
rule_names = {
    "CG-RULE-001": "Privileged Breakout Utility (nsenter, unshare, chroot, modprobe)",
    "CG-RULE-002": "Writable Directory Execution (/tmp, /dev/shm, /var/tmp)",
    "CG-RULE-003": "Interactive Shell Spawned in Container (/bin/sh)"
}

# Map alert sequence numbers to rule IDs
alert_map = {}
for a in alerts:
    rid = a.get("rule_id")
    ev = a.get("event", {})
    seq = ev.get("seq_num")
    if seq is not None:
        alert_map.setdefault(seq, set()).add(rid)

metrics = {}
for r in rules:
    metrics[r] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

total_benign_events = 0
total_attack_events = 0

for ev in events:
    is_container = (ev.get("attribution_state") == "RESOLVED")
    filename = ev.get("filename", "")
    comm = ev.get("comm", "")
    seq = ev.get("seq_num")

    # Determine ground truth for each rule
    gt_r1 = is_container and any(filename.endswith("/" + s) or filename == s for s in ["nsenter", "unshare", "chroot", "modprobe"])
    gt_r2 = is_container and any(filename.startswith(p) for p in ["/tmp/", "/dev/shm/", "/var/tmp/"])
    gt_r3 = is_container and filename in ["/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash"]

    # Overall ground truth
    is_attack = gt_r1 or gt_r2 or gt_r3
    if is_attack:
        total_attack_events += 1
    else:
        total_benign_events += 1

    triggered = alert_map.get(seq, set())

    # Evaluate CG-RULE-001
    pred_r1 = ("CG-RULE-001" in triggered)
    if gt_r1 and pred_r1:
        metrics["CG-RULE-001"]["TP"] += 1
    elif not gt_r1 and pred_r1:
        metrics["CG-RULE-001"]["FP"] += 1
    elif not gt_r1 and not pred_r1:
        metrics["CG-RULE-001"]["TN"] += 1
    elif gt_r1 and not pred_r1:
        metrics["CG-RULE-001"]["FN"] += 1

    # Evaluate CG-RULE-002
    pred_r2 = ("CG-RULE-002" in triggered)
    if gt_r2 and pred_r2:
        metrics["CG-RULE-002"]["TP"] += 1
    elif not gt_r2 and pred_r2:
        metrics["CG-RULE-002"]["FP"] += 1
    elif not gt_r2 and not pred_r2:
        metrics["CG-RULE-002"]["TN"] += 1
    elif gt_r2 and not pred_r2:
        metrics["CG-RULE-002"]["FN"] += 1

    # Evaluate CG-RULE-003
    pred_r3 = ("CG-RULE-003" in triggered)
    if gt_r3 and pred_r3:
        metrics["CG-RULE-003"]["TP"] += 1
    elif not gt_r3 and pred_r3:
        metrics["CG-RULE-003"]["FP"] += 1
    elif not gt_r3 and not pred_r3:
        metrics["CG-RULE-003"]["TN"] += 1
    elif gt_r3 and not pred_r3:
        metrics["CG-RULE-003"]["FN"] += 1

evaluation_results = {}
for r in rules:
    m = metrics[r]
    tp, fp, tn, fn = m["TP"], m["FP"], m["TN"], m["FN"]
    precision = (tp / (tp + fp) * 100.0) if (tp + fp) > 0 else 100.0
    recall = (tp / (tp + fn) * 100.0) if (tp + fn) > 0 else 100.0
    specificity = (tn / (tn + fp) * 100.0) if (tn + fp) > 0 else 100.0
    fpr = (fp / (fp + tn) * 100.0) if (fp + tn) > 0 else 0.0

    evaluation_results[r] = {
        "rule_name": rule_names[r],
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "precision_pct": round(precision, 2),
        "recall_sensitivity_pct": round(recall, 2),
        "specificity_pct": round(specificity, 2),
        "false_positive_rate_pct": round(fpr, 2)
    }

final_report = {
    "corpus_summary": {
        "total_events": len(events),
        "benign_developer_events": total_benign_events,
        "attack_simulation_events": total_attack_events,
        "total_alerts_emitted": len(alerts)
    },
    "rules_evaluation": evaluation_results
}

with open(report_path, "w") as f:
    json.dump(final_report, f, indent=2)

print("\n" + "="*70)
print(" DETECTION VALIDATION & FALSE-POSITIVE EVALUATION SUMMARY")
print("="*70)
print(f" Total Workload Events Evaluated:  {len(events)}")
print(f" Benign Developer Events:         {total_benign_events}")
print(f" Attack Simulation Events:        {total_attack_events}")
print(f" Total Alerts Emitted:            {len(alerts)}")
print("-" * 70)
for r in rules:
    res = evaluation_results[r]
    cm = res["confusion_matrix"]
    print(f" Rule: {r} - {res['rule_name']}")
    print(f"   TP: {cm['TP']} | FP: {cm['FP']} | TN: {cm['TN']} | FN: {cm['FN']}")
    print(f"   Precision: {res['precision_pct']:.2f}% | Recall: {res['recall_sensitivity_pct']:.2f}%")
    print(f"   Specificity: {res['specificity_pct']:.2f}% | False Positive Rate (FPR): {res['false_positive_rate_pct']:.2f}%")
    print("-" * 70)
print("="*70)
PYEOF

echo "[+] Phase I detection benchmark finished. Report saved to ${REPORT_JSON}."
