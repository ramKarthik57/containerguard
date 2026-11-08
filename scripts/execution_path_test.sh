#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Output directory selection:
# Default: Writes new execution evidence to a collision-resistant timestamped run subdirectory
# (docs/evidence/phase_i/runs/<run_id>) to protect the committed baseline evidence in docs/evidence/phase_i/
# from accidental deletion or overwriting.
# Pass "baseline" as first argument to deliberately regenerate docs/evidence/phase_i/.
# Alternatively, pass a custom directory path as first argument.
if [[ "${1:-}" == "baseline" ]]; then
    EVIDENCE_DIR="${ROOT_DIR}/docs/evidence/phase_i"
elif [[ -n "${1:-}" ]]; then
    EVIDENCE_DIR="${1}"
else
    RUN_ID="run_$(date +%Y%m%d_%H%M%S)_$$_${RANDOM}"
    EVIDENCE_DIR="${ROOT_DIR}/docs/evidence/phase_i/runs/${RUN_ID}"
fi

mkdir -p "${EVIDENCE_DIR}"

EVENTS_LOG="${EVIDENCE_DIR}/exec_paths_events.jsonl"
ALERTS_LOG="${EVIDENCE_DIR}/exec_paths_alerts.jsonl"
DAEMON_LOG="${EVIDENCE_DIR}/exec_paths.log"
REPORT_JSON="${EVIDENCE_DIR}/execution_path_report.json"
TEST_PIDS_JSON="${EVIDENCE_DIR}/test_pids.json"

rm -f "${EVENTS_LOG}" "${ALERTS_LOG}" "${DAEMON_LOG}" "${REPORT_JSON}" "${TEST_PIDS_JSON}"

SETUID_RUNNER="${EVIDENCE_DIR}/cg_setuid_runner"
DAEMON_PID=""

# Cleanup trap to guarantee privileged runners and daemon are torn down safely
cleanup() {
    if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        sudo kill -TERM "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi
    if [[ -f "${SETUID_RUNNER}" ]]; then
        sudo rm -f "${SETUID_RUNNER}" 2>/dev/null || true
    fi
    if [[ -d "/sys/fs/cgroup/cg_mig_test_grp1" ]]; then
        sudo rmdir "/sys/fs/cgroup/cg_mig_test_grp1" 2>/dev/null || true
    fi
    if [[ -d "/sys/fs/cgroup/cg_mig_test_grp2" ]]; then
        sudo rmdir "/sys/fs/cgroup/cg_mig_test_grp2" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "================================================================="
echo " ContainerGuard Phase I: Execution-Path & Adversarial Telemetry"
echo " Target Evidence Directory: ${EVIDENCE_DIR}"
echo "================================================================="

# Compile test harness if not present
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

# 2. Execute diverse execution paths with process-specific PID tracking
echo "[2/6] Dispatching execution paths..."

# Dictionary mapping mode to dispatched PID
# Note: test_exec_paths <mode> executes execve in-place without forking,
# so the spawned PID exactly matches the TGID recorded by the kernel tracepoint.
declare -A PIDS

dispatch_test() {
    local mode="$1"
    local bin="$2"
    shift 2
    "${bin}" "$@" &
    local p=$!
    PIDS["${mode}"]="${p}"
    wait "${p}" || true
}

echo "  -> Standard execve..."
dispatch_test "standard_execve" "${ROOT_DIR}/bin/test_exec_paths" standard_execve

echo "  -> Direct syscall (SYS_execve)..."
dispatch_test "direct_syscall" "${ROOT_DIR}/bin/test_exec_paths" direct_syscall

echo "  -> execveat with relative dirfd..."
dispatch_test "execveat_relative" "${ROOT_DIR}/bin/test_exec_paths" execveat_relative

echo "  -> execveat with memfd & AT_EMPTY_PATH..."
dispatch_test "execveat_memfd" "${ROOT_DIR}/bin/test_exec_paths" execveat_memfd

echo "  -> Shebang script (#/bin/sh)..."
dispatch_test "shebang" "${ROOT_DIR}/bin/test_exec_paths" shebang

echo "  -> Symlink execution..."
dispatch_test "symlink" "${ROOT_DIR}/bin/test_exec_paths" symlink

echo "  -> Failed exec attempt (ENOENT - file not found)..."
dispatch_test "fail_enoent" "${ROOT_DIR}/bin/test_exec_paths" fail_enoent

echo "  -> Failed exec attempt (EACCES - permission denied)..."
dispatch_test "fail_eacces" "${ROOT_DIR}/bin/test_exec_paths" fail_eacces

echo "  -> Pathname truncation (> 256 bytes)..."
dispatch_test "path_truncation" "${ROOT_DIR}/bin/test_exec_paths" path_truncation

echo "  -> Comm truncation (16 chars)..."
dispatch_test "comm_truncation" "${ROOT_DIR}/bin/test_exec_paths" comm_truncation

echo "  -> Static ELF execution..."
dispatch_test "static_elf" /tmp/cg_static_test

echo "  -> Harmless setuid binary execution (unprivileged -> EUID 0 transition)..."
# Compile into an isolated ephemeral helper in EVIDENCE_DIR to strictly preserve bin/cg_setuid_test
gcc -O2 "${ROOT_DIR}/cmd/test_exec_paths/setuid_test.c" -o "${SETUID_RUNNER}"
sudo chown root:root "${SETUID_RUNNER}"
sudo chmod 4755 "${SETUID_RUNNER}"
dispatch_test "setuid_transition" "${SETUID_RUNNER}"
sudo rm -f "${SETUID_RUNNER}"

# Persist dispatched PIDs into test_pids.json for rigorous verification
PID_ARGS=()
for k in "${!PIDS[@]}"; do
    PID_ARGS+=("${k}=${PIDS[$k]}")
    echo "  [PID] ${k} -> ${PIDS[$k]}"
done

python3 -c '
import sys, json
path = sys.argv[1]
data = {}
for arg in sys.argv[2:]:
    if "=" in arg:
        k, v = arg.split("=", 1)
        data[k] = int(v)
with open(path, "w") as f:
    json.dump(data, f, indent=2)
' "${TEST_PIDS_JSON}" "${PID_ARGS[@]}"

# 3. Containerized executions
echo "[3/6] Dispatching containerized executions..."
# Ensure baseline research containers exist and are in running state
for c in cg-test-a cg-test-b-event-test; do
    if ! sudo docker ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
        echo "  -> Initializing missing container ${c}..."
        sudo docker run -d --name "${c}" busybox:latest sleep 3600
    fi
    if ! sudo docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        echo "  -> Starting container ${c}..."
        sudo docker start "${c}" >/dev/null
    fi
done

sudo docker exec cg-test-a /bin/date
sudo docker exec cg-test-a /bin/echo "container A live workload"
sudo docker exec cg-test-b-event-test /bin/uname -a

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
if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
    sudo kill -TERM "${DAEMON_PID}" || true
    wait "${DAEMON_PID}" 2>/dev/null || true
    DAEMON_PID=""
fi

echo "[+] ContainerGuard stopped gracefully."

# 6. Evaluate and compile empirical report with process-specific validation
echo "[6/6] Compiling Execution Path and Adversarial Telemetry Evaluation..."

python3 - "${EVIDENCE_DIR}" << 'PYEOF'
import json
import os
import re
import sys

evidence_dir = sys.argv[1] if len(sys.argv) > 1 else "docs/evidence/phase_i"
events_log = os.path.join(evidence_dir, "exec_paths_events.jsonl")
daemon_log = os.path.join(evidence_dir, "exec_paths.log")
report_path = os.path.join(evidence_dir, "execution_path_report.json")
test_pids_path = os.path.join(evidence_dir, "test_pids.json")

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

# Required execution test keys that must be present in live runs
REQUIRED_PID_KEYS = [
    "standard_execve",
    "direct_syscall",
    "execveat_relative",
    "execveat_memfd",
    "shebang",
    "symlink",
    "fail_enoent",
    "fail_eacces",
    "path_truncation",
    "comm_truncation",
    "static_elf",
    "setuid_transition"
]

# Load dispatched PIDs for process-specific correlation
dispatched_pids = {}
if os.path.exists(test_pids_path):
    with open(test_pids_path, "r") as f:
        dispatched_pids = json.load(f)
    
    missing_keys = [k for k in REQUIRED_PID_KEYS if k not in dispatched_pids]
    if missing_keys:
        print(f"\n[!] PID VALIDATION FAILURE: test_pids.json is missing required test keys: {missing_keys}")
        sys.exit(1)
else:
    # Historical baseline archive evaluation fallback
    # Only permitted when evaluating archives that genuinely lack test_pids.json
    print("[*] Notice: test_pids.json not found; reconstructing test TGIDs from historical event sequence...")
    test_tgids = []
    for e in events:
        tg = e.get("tgid")
        if "test_exec_paths" in e.get("filename", "") and tg not in test_tgids:
            test_tgids.append(tg)
    if len(test_tgids) >= 10:
        dispatched_pids = {
            "standard_execve": test_tgids[0],
            "direct_syscall": test_tgids[1],
            "execveat_relative": test_tgids[2],
            "execveat_memfd": test_tgids[3],
            "shebang": test_tgids[4],
            "symlink": test_tgids[5],
            "fail_enoent": test_tgids[6],
            "fail_eacces": test_tgids[7],
            "path_truncation": test_tgids[8],
            "comm_truncation": test_tgids[9],
        }

# Analyze observed execution features
execveat_count = sum(1 for e in events if e.get("execveat"))
at_empty_path_count = sum(1 for e in events if e.get("at_empty_path"))
path_truncated_count = sum(1 for e in events if e.get("path_truncated"))
comm_truncated_count = sum(1 for e in events if e.get("comm_truncated"))
failed_count = sum(1 for e in events if e.get("failed"))
committed_count = sum(1 for e in events if e.get("committed"))
cgroup_migrated_count = sum(1 for e in events if e.get("cgroup_migrated"))

# Process-correlated validation assertions:
# 1. Standard execve: event TGID matches standard_execve PID executing /bin/true via libc
pid_std = dispatched_pids.get("standard_execve")
has_standard_exec = any(
    (e.get("tgid") == pid_std if pid_std else True)
    and e.get("filename") == "/bin/true"
    and not e.get("execveat")
    and not e.get("cgroup_migrated")
    for e in events
)

# 2. Direct syscall (SYS_execve): event TGID specifically matches direct_syscall PID,
# completely decoupled from comm_truncation or cgroup_migration executions
pid_direct = dispatched_pids.get("direct_syscall")
has_direct_syscall = any(
    e.get("tgid") == pid_direct
    and e.get("filename") == "/bin/true"
    and not e.get("execveat")
    and not e.get("cgroup_migrated")
    for e in events
) if pid_direct else False

# 3. Relative execveat: event TGID matches execveat_relative PID with execveat=True and at_empty_path=False
pid_rel = dispatched_pids.get("execveat_relative")
has_execveat_relative = any(
    (e.get("tgid") == pid_rel if pid_rel else True)
    and e.get("execveat")
    and not e.get("at_empty_path")
    for e in events
)

# 4. Anonymous memfd execveat: event TGID matches execveat_memfd PID with execveat=True and at_empty_path=True
pid_memfd = dispatched_pids.get("execveat_memfd")
has_memfd = any(
    (e.get("tgid") == pid_memfd if pid_memfd else True)
    and e.get("execveat")
    and e.get("at_empty_path")
    for e in events
)

# 5. Shebang script execution
pid_shebang = dispatched_pids.get("shebang")
has_shebang = any(
    (e.get("tgid") == pid_shebang if pid_shebang else True)
    and "cg_test_shebang" in e.get("filename", "")
    for e in events
)

# 6. Symlink traversal
pid_sym = dispatched_pids.get("symlink")
has_symlink = any(
    (e.get("tgid") == pid_sym if pid_sym else True)
    and "cg_test_symlink" in e.get("filename", "")
    for e in events
)

# 7. Static ELF binary execution
has_static_elf = any("cg_static_test" in e.get("filename", "") for e in events)

# 8. Failed executions with exact exit codes
pid_enoent = dispatched_pids.get("fail_enoent")
has_enoent = any(
    (e.get("tgid") == pid_enoent if pid_enoent else True)
    and e.get("failed")
    and e.get("exit_code") == -2
    for e in events
)

pid_eacces = dispatched_pids.get("fail_eacces")
has_eacces = any(
    (e.get("tgid") == pid_eacces if pid_eacces else True)
    and e.get("failed")
    and e.get("exit_code") == -13
    for e in events
)

# 9. Pathname and Comm truncation boundary enforcement
pid_path_trunc = dispatched_pids.get("path_truncation")
has_path_trunc = any(
    (e.get("tgid") == pid_path_trunc if pid_path_trunc else True)
    and e.get("path_truncated")
    for e in events
)

pid_comm_trunc = dispatched_pids.get("comm_truncation")
has_comm_trunc = any(
    (e.get("tgid") == pid_comm_trunc if pid_comm_trunc else True)
    and e.get("comm_truncated")
    for e in events
)

# 10. Setuid transition: genuine UID 1000 -> EUID 0 credential elevation
pid_setuid = dispatched_pids.get("setuid_transition")
has_setuid_transition = any(
    (e.get("tgid") == pid_setuid if pid_setuid else True)
    and ("cg_setuid_test" in e.get("filename", "") or "cg_setuid_runner" in e.get("filename", ""))
    and e.get("uid") != e.get("euid")
    and e.get("setuid_exec")
    and e.get("euid") == 0
    for e in events
)

# 11. Container workload attribution and cgroup migration
has_container_event = any(e.get("attribution_state") == "RESOLVED" for e in events)

# Validate presence and completeness of final telemetry integrity report
if not accounting:
    print(f"\n[!] ACCOUNTING FAILURE: No final telemetry accounting report found in {daemon_log}!")
    sys.exit(1)

hook_calls = accounting.get("kernel_hook_invocations", 0)
submitted = accounting.get("kernel_ringbuf_submitted", 0)
drops = accounting.get("kernel_ringbuf_reserve_drops", 0)
decoded = accounting.get("userspace_records_decoded", 0)
decode_failures = accounting.get("userspace_decode_failures", 0)
queue_overflows = accounting.get("userspace_queue_overflows", 0)
sequence_gaps = accounting.get("sequence_gaps_detected", 0)
userspace_loss = accounting.get("userspace_loss_count", 0)

if hook_calls == 0 or submitted == 0:
    print(f"\n[!] ACCOUNTING FAILURE: Zero hook invocations ({hook_calls}) or submissions ({submitted}) recorded!")
    sys.exit(1)

conservation_valid = (hook_calls == submitted + drops)
if not conservation_valid:
    print(f"\n[!] CONSERVATION VIOLATION: Hooks ({hook_calls}) != Submissions ({submitted}) + Drops ({drops})")
    sys.exit(1)

if decoded != submitted:
    print(f"\n[!] INCOMPLETE TELEMETRY DELIVERY: Decoded ({decoded}) != Submissions ({submitted}) (Loss: {submitted - decoded})")
    sys.exit(1)

if decode_failures > 0:
    print(f"\n[!] DECODE FAILURE: {decode_failures} record decode failures!")
    sys.exit(1)

if queue_overflows > 0:
    print(f"\n[!] QUEUE OVERFLOW: {queue_overflows} userspace queue overflows!")
    sys.exit(1)

if sequence_gaps > 0:
    print(f"\n[!] SEQUENCE INTEGRITY FAILURE: {sequence_gaps} sequence gaps detected!")
    sys.exit(1)

if userspace_loss > 0:
    print(f"\n[!] USERSPACE LOSS FAILURE: {userspace_loss} lost events accounted!")
    sys.exit(1)

delivery_rate_pct = (decoded / submitted * 100.0) if submitted > 0 else 0.0

report = {
    "summary": {
        "total_events_captured": len(events),
        "kernel_hook_calls": hook_calls,
        "kernel_submissions": submitted,
        "kernel_reserve_drops": drops,
        "userspace_decoded": decoded,
        "userspace_decode_failures": decode_failures,
        "userspace_queue_overflows": queue_overflows,
        "sequence_gaps_detected": sequence_gaps,
        "userspace_loss_count": userspace_loss,
        "conservation_satisfied": conservation_valid,
        "delivery_rate_percent": round(delivery_rate_pct, 4)
    },
    "execution_path_coverage": {
        "standard_execve": has_standard_exec,
        "direct_syscall_execve": has_direct_syscall,
        "execveat_relative": has_execveat_relative,
        "execveat_at_empty_path_memfd": has_memfd,
        "shebang_script": has_shebang,
        "symlink_traversal": has_symlink,
        "static_elf_binary": has_static_elf,
        "setuid_euid_transition": has_setuid_transition,
        "failed_exec_enoent": has_enoent,
        "failed_exec_eacces": has_eacces,
        "pathname_truncation": has_path_trunc,
        "comm_truncation": has_comm_trunc,
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
    "kernel_accounting": accounting,
    "dispatched_pids": dispatched_pids
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
print(" Execution Path Coverage (Correlated):")
for k, v in report["execution_path_coverage"].items():
    print(f"   - {k:32s}: {'PASS' if v else 'FAIL'}")

# Explicit assertion check: fail execution if any execution pathway was missed
failed_assertions = [k for k, v in report["execution_path_coverage"].items() if not v]
if failed_assertions:
    print(f"\n[!] EXECUTION PATH ASSERTION FAILED: Missing coverage for: {failed_assertions}")
    sys.exit(1)
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
