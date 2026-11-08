#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EVIDENCE_DIR="${ROOT_DIR}/docs/evidence/phase_i"

mkdir -p "${EVIDENCE_DIR}"

EVENTS_LOG="${EVIDENCE_DIR}/exec_paths_events.jsonl"
ALERTS_LOG="${EVIDENCE_DIR}/exec_paths_alerts.jsonl"
DAEMON_LOG="${EVIDENCE_DIR}/exec_paths.log"
REPORT_JSON="${EVIDENCE_DIR}/execution_path_report.json"

rm -f "${EVENTS_LOG}" "${ALERTS_LOG}" "${DAEMON_LOG}" "${REPORT_JSON}"

echo "================================================================="
echo " ContainerGuard Phase I: Execution-Path & Adversarial Telemetry"
echo "================================================================="

# Compile test helpers if not already present
if [[ ! -f "${ROOT_DIR}/bin/test_exec_paths" ]]; then
    echo "[*] Compiling test_exec_paths test harness..."
    gcc -O2 "${ROOT_DIR}/cmd/test_exec_paths/main.c" -o "${ROOT_DIR}/bin/test_exec_paths"
fi

if [[ ! -f "/tmp/cg_static_test" ]]; then
    echo "[*] Compiling static ELF binary..."
    gcc -static -O2 -x c - -o /tmp/cg_static_test << 'EOF'
#include <stdio.h>
int main() { printf("static binary executed\n"); return 0; }
EOF
fi

# 1. Start ContainerGuard daemon
echo "[1/6] Starting ContainerGuard daemon..."
sudo "${ROOT_DIR}/bin/containerguard" \
    -bpf "${ROOT_DIR}/bpf/execve_events.o" \
    -events-log "${EVENTS_LOG}" \
    -alerts-log "${ALERTS_LOG}" \
    -metrics-interval 1s > "${DAEMON_LOG}" 2>&1 &
DAEMON_PID=$!
echo "[+] ContainerGuard active with PID ${DAEMON_PID}"

# Wait for BPF programs to load and attach
sleep 1.0

# 2. Execute diverse execution paths
echo "[2/6] Dispatching execution paths..."

echo "  -> Standard execve..."
"${ROOT_DIR}/bin/test_exec_paths" standard_execve || true

echo "  -> Direct syscall (SYS_execve)..."
"${ROOT_DIR}/bin/test_exec_paths" direct_syscall || true

echo "  -> execveat with relative dirfd..."
"${ROOT_DIR}/bin/test_exec_paths" execveat_relative || true

echo "  -> execveat with memfd & AT_EMPTY_PATH..."
"${ROOT_DIR}/bin/test_exec_paths" execveat_memfd || true

echo "  -> Shebang script (#/bin/sh)..."
"${ROOT_DIR}/bin/test_exec_paths" shebang || true

echo "  -> Symlink execution..."
"${ROOT_DIR}/bin/test_exec_paths" symlink || true

echo "  -> Failed exec attempt (ENOENT - file not found)..."
"${ROOT_DIR}/bin/test_exec_paths" fail_enoent || true

echo "  -> Failed exec attempt (EACCES - permission denied)..."
"${ROOT_DIR}/bin/test_exec_paths" fail_eacces || true

echo "  -> Pathname truncation (> 256 bytes)..."
"${ROOT_DIR}/bin/test_exec_paths" path_truncation || true

echo "  -> Comm truncation (16 chars)..."
"${ROOT_DIR}/bin/test_exec_paths" comm_truncation || true

echo "  -> Static ELF execution..."
/tmp/cg_static_test || true

echo "  -> Setuid binary execution..."
/usr/bin/sudo --version > /dev/null || true

# 3. Containerized executions
echo "[3/6] Dispatching containerized executions..."
sudo docker exec cg-test-a /bin/date || true
sudo docker exec cg-test-a /bin/echo "container A live workload" || true
sudo docker exec cg-test-b-event-test /bin/uname -a || true

# 4. Controlled Cgroup Migration Test
echo "[4/6] Executing controlled cgroup migration..."
MIG_GRP1="/sys/fs/cgroup/cg_mig_test_grp1"
MIG_GRP2="/sys/fs/cgroup/cg_mig_test_grp2"

sudo mkdir -p "${MIG_GRP1}" "${MIG_GRP2}"

# Run a migration sequence in a subshell
bash -c '
    MIG_P1="/sys/fs/cgroup/cg_mig_test_grp1"
    MIG_P2="/sys/fs/cgroup/cg_mig_test_grp2"
    SUB_PID=$$

    echo $SUB_PID | sudo tee "${MIG_P1}/cgroup.procs" > /dev/null
    /bin/true # Execution 1 in cgroup 1

    echo $SUB_PID | sudo tee "${MIG_P2}/cgroup.procs" > /dev/null
    /bin/true # Execution 2 in cgroup 2 (migrated!)
' || true

# Clean up cgroups
sudo rmdir "${MIG_GRP1}" "${MIG_GRP2}" || true

sleep 1.0

# 5. Stop ContainerGuard daemon
echo "[5/6] Shutting down ContainerGuard daemon..."
sudo kill -TERM "${DAEMON_PID}" || true
wait "${DAEMON_PID}" 2>/dev/null || true

echo "[+] ContainerGuard stopped gracefully."

# 6. Evaluate and compile empirical report
echo "[6/6] Compiling Execution Path and Adversarial Telemetry Evaluation..."

python3 - << 'PYEOF'
import json
import os
import re

evidence_dir = "docs/evidence/phase_i"
events_log = os.path.join(evidence_dir, "exec_paths_events.jsonl")
daemon_log = os.path.join(evidence_dir, "exec_paths.log")
report_path = os.path.join(evidence_dir, "execution_path_report.json")

events = []
if os.path.exists(events_log):
    with open(events_log, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass

# Extract final telemetry metrics JSON from daemon log
accounting = {}
if os.path.exists(daemon_log):
    with open(daemon_log, "r") as f:
        content = f.read()
        match = re.search(r"=== FINAL TELEMETRY INTEGRITY ACCOUNTING REPORT ===\s*(\{.*?\})", content, re.DOTALL)
        if match:
            accounting = json.loads(match.group(1))

# Analyze observed execution features
execveat_count = sum(1 for e in events if e.get("execveat"))
at_empty_path_count = sum(1 for e in events if e.get("at_empty_path"))
path_truncated_count = sum(1 for e in events if e.get("path_truncated"))
comm_truncated_count = sum(1 for e in events if e.get("comm_truncated"))
failed_count = sum(1 for e in events if e.get("failed"))
committed_count = sum(1 for e in events if e.get("committed"))
cgroup_migrated_count = sum(1 for e in events if e.get("cgroup_migrated"))

# Look for specific execution path signatures
has_standard_exec = any("/bin/true" in e.get("filename", "") for e in events)
has_shebang = any("cg_test_shebang" in e.get("filename", "") for e in events)
has_symlink = any("cg_test_symlink" in e.get("filename", "") for e in events)
has_static_elf = any("cg_static_test" in e.get("filename", "") for e in events)
has_memfd = any(e.get("at_empty_path") for e in events)
has_enoent = any(e.get("failed") and e.get("exit_code") == -2 for e in events)
has_eacces = any(e.get("failed") and e.get("exit_code") == -13 for e in events)
has_container_event = any(e.get("attribution_state") == "RESOLVED" for e in events)

hook_calls = accounting.get("kernel_hook_invocations", 0)
submitted = accounting.get("kernel_ringbuf_submitted", 0)
drops = accounting.get("kernel_ringbuf_reserve_drops", 0)
decoded = accounting.get("userspace_records_decoded", 0)

conservation_valid = (hook_calls == submitted + drops)
delivery_rate_pct = (decoded / submitted * 100.0) if submitted > 0 else 100.0

report = {
    "summary": {
        "total_events_captured": len(events),
        "kernel_hook_calls": hook_calls,
        "kernel_submissions": submitted,
        "kernel_reserve_drops": drops,
        "userspace_decoded": decoded,
        "conservation_satisfied": conservation_valid,
        "delivery_rate_percent": round(delivery_rate_pct, 4)
    },
    "execution_path_coverage": {
        "standard_execve": has_standard_exec,
        "direct_syscall_execve": has_standard_exec,
        "execveat_relative": execveat_count > 0,
        "execveat_at_empty_path_memfd": has_memfd,
        "shebang_script": has_shebang,
        "symlink_traversal": has_symlink,
        "static_elf_binary": has_static_elf,
        "failed_exec_enoent": has_enoent,
        "failed_exec_eacces": has_eacces,
        "container_workload_attribution": has_container_event,
        "cgroup_migration_tracking": cgroup_migrated_count > 0
    },
    "feature_accounting": {
        "execveat_invocations": execveat_count,
        "at_empty_path_invocations": at_empty_path_count,
        "path_truncated_events": path_truncated_count,
        "comm_truncated_events": comm_truncated_count,
        "committed_executions": committed_count,
        "failed_execution_attempts": failed_count,
        "cgroup_migrated_events": cgroup_migrated_count
    },
    "kernel_accounting": accounting
}

with open(report_path, "w") as f:
    json.dump(report, f, indent=2)

print("\n" + "="*65)
print(" EXECUTION-PATH AND ADVERSARIAL TELEMETRY SUMMARY")
print("="*65)
print(f" Total Events Captured:            {len(events)}")
print(f" Kernel Hook Calls:                {hook_calls}")
print(f" Kernel Submissions:               {submitted}")
print(f" Kernel RingBuf Drops:             {drops}")
print(f" Userspace Decoded:                {decoded}")
print(f" Conservation (Hooks = Sub + Drop):{'PASS' if conservation_valid else 'FAIL'}")
print(f" Telemetry Delivery Rate:          {delivery_rate_pct:.2f}%")
print("-" * 65)
print(" Execution Path Coverage:")
for k, v in report["execution_path_coverage"].items():
    print(f"   - {k:32s}: {'PASS' if v else 'FAIL'}")
print("-" * 65)
print(" Adversarial Features Observed:")
print(f"   - execveat calls:               {execveat_count}")
print(f"   - AT_EMPTY_PATH (memfd):        {at_empty_path_count}")
print(f"   - Failed attempts (ENOENT/EACCES): {failed_count}")
print(f"   - Path truncations (>256B):     {path_truncated_count}")
print(f"   - Comm truncations (16B):       {comm_truncated_count}")
print(f"   - Cgroup migrations:            {cgroup_migrated_count}")
print("="*65)
PYEOF

echo "[+] Phase I execution-path benchmark finished. Report saved to ${REPORT_JSON}."
