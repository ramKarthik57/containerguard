#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Output directory and mode selection:
# Default: Writes new execution evidence to a collision-resistant timestamped run subdirectory
# (docs/evidence/phase_i/runs/<run_id>) to protect the committed baseline evidence in docs/evidence/phase_i/.
# Pass "--archive-eval" to evaluate the historical baseline archive in non-destructive read-only mode without re-running tests.
ARCHIVE_MODE="false"
if [[ "${1:-}" == "baseline" || "${1:-}" == "--baseline" ]]; then
    echo "Error: 'baseline' and '--baseline' modes have been removed to protect evidence immutability." >&2
    echo "       To evaluate historical baseline evidence non-destructively, use: --archive-eval" >&2
    echo "       To run a live reproduction test, run without arguments (or specify a custom run directory)." >&2
    exit 1
elif [[ "${1:-}" == "--archive-eval" ]]; then
    EVIDENCE_DIR="${ROOT_DIR}/docs/evidence/phase_i"
    ARCHIVE_MODE="true"
    if [[ ! -d "${EVIDENCE_DIR}" ]]; then
        echo "Error: Baseline evidence directory '${EVIDENCE_DIR}' does not exist." >&2
        exit 1
    fi
    if [[ ! -f "${EVIDENCE_DIR}/exec_paths_events.jsonl" || ! -f "${EVIDENCE_DIR}/exec_paths.log" ]]; then
        echo "Error: Required baseline evidence files missing from '${EVIDENCE_DIR}'." >&2
        exit 1
    fi
elif [[ -n "${1:-}" ]]; then
    # Prevent live tests from targeting the frozen baseline directory
    NORM_TARGET="$(realpath -m "${1}")"
    NORM_BASELINE="$(realpath -m "${ROOT_DIR}/docs/evidence/phase_i")"
    if [[ "${NORM_TARGET}" == "${NORM_BASELINE}" ]]; then
        echo "Error: Cannot run live tests directly in docs/evidence/phase_i. Baseline evidence is immutable." >&2
        echo "       All live runs must output to an isolated run directory (e.g. docs/evidence/phase_i/runs/<run_id>)." >&2
        exit 1
    fi
    if [[ -e "${NORM_TARGET}" ]]; then
        echo "Error: Custom output directory '${1}' already exists." >&2
        echo "       Live runs require a new directory path to ensure exclusive creation and clean evidence isolation." >&2
        exit 1
    fi
    mkdir -p "$(dirname "${NORM_TARGET}")"
    if ! mkdir "${NORM_TARGET}"; then
        echo "Error: Failed to create custom output directory '${1}' exclusively." >&2
        exit 1
    fi
    EVIDENCE_DIR="${NORM_TARGET}"
    RUN_ID="$(basename "${EVIDENCE_DIR}")"
else
    RUNS_BASE_DIR="${ROOT_DIR}/docs/evidence/phase_i/runs"
    mkdir -p "${RUNS_BASE_DIR}"
    RUN_ID="run_$(date +%Y%m%d_%H%M%S)_$$_${RANDOM}"
    EVIDENCE_DIR="${RUNS_BASE_DIR}/${RUN_ID}"
    if ! mkdir "${EVIDENCE_DIR}"; then
        echo "Error: Failed to create exclusive run directory '${EVIDENCE_DIR}'." >&2
        exit 1
    fi
fi

EVENTS_LOG="${EVIDENCE_DIR}/exec_paths_events.jsonl"
ALERTS_LOG="${EVIDENCE_DIR}/exec_paths_alerts.jsonl"
DAEMON_LOG="${EVIDENCE_DIR}/exec_paths.log"
REPORT_JSON="${EVIDENCE_DIR}/execution_path_report.json"
TEST_PIDS_JSON="${EVIDENCE_DIR}/test_pids.json"
SUPERVISOR_MANIFEST="${EVIDENCE_DIR}/supervisor_manifest.json"

# In live run mode, purge any previous artifacts in the run directory.
if [[ "${ARCHIVE_MODE}" != "true" ]]; then
    rm -f "${EVENTS_LOG}" "${ALERTS_LOG}" "${DAEMON_LOG}" "${REPORT_JSON}" "${TEST_PIDS_JSON}" "${SUPERVISOR_MANIFEST}"
fi

DAEMON_PID=""
SUPERVISOR_JOB_PID=""
CREATED_SETUID_RUNNER="false"
SETUID_RUNNER_PATH=""
CREATED_MIG_GRP1="false"
CREATED_MIG_GRP2="false"
MIG_GRP1="/sys/fs/cgroup/cg_mig_test_grp1"
MIG_GRP2="/sys/fs/cgroup/cg_mig_test_grp2"

# Cleanup trap to guarantee privileged runners and daemon are torn down safely (live runs only)
cleanup() {
    if [[ "${ARCHIVE_MODE}" == "true" ]]; then
        return 0
    fi
    if [[ -n "${SUPERVISOR_JOB_PID}" ]] && kill -0 "${SUPERVISOR_JOB_PID}" 2>/dev/null; then
        kill -TERM "${SUPERVISOR_JOB_PID}" 2>/dev/null || true
        wait "${SUPERVISOR_JOB_PID}" 2>/dev/null || true
    fi
    if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        sudo kill -TERM "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi
    if [[ "${CREATED_MIG_GRP1}" == "true" && -d "${MIG_GRP1}" ]]; then
        sudo rmdir "${MIG_GRP1}" 2>/dev/null || true
        CREATED_MIG_GRP1="false"
    fi
    if [[ "${CREATED_MIG_GRP2}" == "true" && -d "${MIG_GRP2}" ]]; then
        sudo rmdir "${MIG_GRP2}" 2>/dev/null || true
        CREATED_MIG_GRP2="false"
    fi
}

if [[ "${ARCHIVE_MODE}" != "true" ]]; then
    trap cleanup EXIT INT TERM
fi

echo "================================================================="
echo " ContainerGuard Phase I: Execution-Path & Adversarial Telemetry"
echo " Target Evidence Directory: ${EVIDENCE_DIR}"
echo " Archive Mode: ${ARCHIVE_MODE}"
echo "================================================================="

if [[ "${ARCHIVE_MODE}" != "true" ]]; then
    # -------------------------------------------------------------
    # 1. Pre-flight Checks & Staging
    # -------------------------------------------------------------
    echo "[1/6] Running pre-flight checks and preparing isolated test harness..."

    # Ensure sudo credentials are authenticated in foreground before backgrounding daemon
    if ! sudo -v; then
        echo "Error: Sudo authentication failed. Live reproduction requires interactive root privileges." >&2
        exit 1
    fi

    # Ensure Docker daemon is accessible
    if ! sudo docker info >/dev/null 2>&1; then
        echo "Error: Docker daemon is not accessible via sudo docker info." >&2
        echo "       Please start Docker (e.g. sudo service docker start) and ensure containers cg-test-a and cg-test-b-event-test exist." >&2
        exit 1
    fi

    # Ensure baseline research containers exist and are in running state
    for c in cg-test-a cg-test-b-event-test; do
        if ! sudo docker ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
            echo "  -> Initializing missing container ${c}..."
            if ! sudo docker run -d --name "${c}" busybox:latest sleep 3600; then
                echo "Error: Failed to initialize required container ${c}." >&2
                exit 1
            fi
        fi
        if ! sudo docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
            echo "  -> Starting container ${c}..."
            if ! sudo docker start "${c}" >/dev/null; then
                echo "Error: Failed to start required container ${c}." >&2
                exit 1
            fi
        fi
    done

    # Pre-flight check: refuse to reuse pre-existing cgroup test directories
    if [[ -d "${MIG_GRP1}" || -d "${MIG_GRP2}" ]]; then
        echo "Error: Cgroup test directory already exists (${MIG_GRP1} or ${MIG_GRP2})." >&2
        echo "       Refusing to reuse or modify pre-existing cgroups. Clean up before testing." >&2
        exit 1
    fi

    if ! sudo mkdir "${MIG_GRP1}"; then
        echo "Error: Failed to create test cgroup ${MIG_GRP1}; refusing to continue." >&2
        exit 1
    fi
    CREATED_MIG_GRP1="true"

    if ! sudo mkdir "${MIG_GRP2}"; then
        echo "Error: Failed to create test cgroup ${MIG_GRP2}; refusing to continue." >&2
        exit 1
    fi
    CREATED_MIG_GRP2="true"

    # Capture cgroup directory inode numbers for definitive telemetry correlation
    CG1_INODE=$(stat -c '%i' "${MIG_GRP1}")
    CG2_INODE=$(stat -c '%i' "${MIG_GRP2}")
    echo "  [cgroup] CG1 created: ${MIG_GRP1} (inode: ${CG1_INODE})"
    echo "  [cgroup] CG2 created: ${MIG_GRP2} (inode: ${CG2_INODE})"

    # Create isolated directory structure for this run
    BUILD_DIR="${EVIDENCE_DIR}/build"
    TARGETS_DIR="${EVIDENCE_DIR}/targets"
    REL_DIR="${EVIDENCE_DIR}/rel_dir"
    SOURCES_DIR="${EVIDENCE_DIR}/harness_sources"
    mkdir -p "${BUILD_DIR}" "${TARGETS_DIR}" "${REL_DIR}" "${SOURCES_DIR}"

    # -------------------------------------------------------------
    # 2. Compile Test Supervisor and Unique Workload Binaries
    # -------------------------------------------------------------
    echo "[2/6] Compiling supervisor and scenario target binaries into ${EVIDENCE_DIR}..."

    SUPERVISOR_SRC="${ROOT_DIR}/cmd/test_supervisor/supervisor.c"
    MIG_P1_SRC="${ROOT_DIR}/cmd/test_supervisor/mig_phase1.c"
    MIG_P2_SRC="${ROOT_DIR}/cmd/test_supervisor/mig_phase2.c"
    TARGET_TEMPLATE_SRC="${ROOT_DIR}/cmd/test_supervisor/target_template.c"
    SETUID_SRC="${ROOT_DIR}/cmd/test_exec_paths/setuid_test.c"

    # Preserve exact harness source code inside evidence directory for independent verification
    cp "${SUPERVISOR_SRC}" "${SOURCES_DIR}/"
    cp "${MIG_P1_SRC}" "${SOURCES_DIR}/"
    cp "${MIG_P2_SRC}" "${SOURCES_DIR}/"
    cp "${TARGET_TEMPLATE_SRC}" "${SOURCES_DIR}/"
    cp "${SETUID_SRC}" "${SOURCES_DIR}/"
    cp "${BASH_SOURCE[0]}" "${SOURCES_DIR}/execution_path_test.sh"

    # Record compiler version and commands in compiler manifest
    GCC_VERSION=$(gcc --version | head -n 1)
    cat << EOF > "${EVIDENCE_DIR}/compiler_manifest.json"
{
  "compiler": "${GCC_VERSION}",
  "commands": {
    "supervisor": "gcc -O2 cmd/test_supervisor/supervisor.c -o build/supervisor",
    "mig_phase1": "gcc -O2 cmd/test_supervisor/mig_phase1.c -o targets/mig_phase1_${RUN_ID}",
    "mig_phase2": "gcc -O2 cmd/test_supervisor/mig_phase2.c -o targets/mig_phase2_${RUN_ID}",
    "target_std_execve": "gcc -O2 cmd/test_supervisor/target_template.c -o targets/target_std_execve",
    "target_direct_syscall": "gcc -O2 cmd/test_supervisor/target_template.c -o targets/target_direct_syscall",
    "relative_execveat": "gcc -O2 cmd/test_supervisor/target_template.c -o rel_dir/relative_execveat_${RUN_ID}",
    "comm_short": "gcc -O2 cmd/test_supervisor/target_template.c -o targets/comm_short",
    "static_elf": "gcc -static -O2 cmd/test_supervisor/target_template.c -o targets/static_elf_${RUN_ID}",
    "setuid_runner": "gcc -O2 cmd/test_exec_paths/setuid_test.c -o targets/setuid_runner_${RUN_ID}"
  }
}
EOF

    gcc -O2 "${SUPERVISOR_SRC}" -o "${BUILD_DIR}/supervisor"
    gcc -O2 "${MIG_P1_SRC}" -o "${TARGETS_DIR}/mig_phase1_${RUN_ID}"
    gcc -O2 "${MIG_P2_SRC}" -o "${TARGETS_DIR}/mig_phase2_${RUN_ID}"
    gcc -O2 "${TARGET_TEMPLATE_SRC}" -o "${TARGETS_DIR}/target_std_execve"
    gcc -O2 "${TARGET_TEMPLATE_SRC}" -o "${TARGETS_DIR}/target_direct_syscall"
    gcc -O2 "${TARGET_TEMPLATE_SRC}" -o "${REL_DIR}/relative_execveat_${RUN_ID}"

    # Isolated comm truncation target: short basename ("comm_short", 10 chars <= 15 chars)
    # This guarantees the telemetry comm_truncated flag is triggered solely by pre-exec PR_SET_NAME.
    gcc -O2 "${TARGET_TEMPLATE_SRC}" -o "${TARGETS_DIR}/comm_short"

    # Static ELF compilation and verification (no PT_INTERP, no DT_NEEDED)
    STATIC_BIN="${TARGETS_DIR}/static_elf_${RUN_ID}"
    gcc -static -O2 "${TARGET_TEMPLATE_SRC}" -o "${STATIC_BIN}"
    if readelf -l "${STATIC_BIN}" | grep -q "INTERP"; then
        echo "Error: static_elf binary contains PT_INTERP dynamic interpreter header!" >&2
        exit 1
    fi
    if readelf -d "${STATIC_BIN}" 2>/dev/null | grep -q "NEEDED"; then
        echo "Error: static_elf binary contains DT_NEEDED dynamic dependency tag!" >&2
        exit 1
    fi
    STATIC_ELF_SHA256=$(sha256sum "${STATIC_BIN}" | awk '{print $1}')
    echo "${STATIC_ELF_SHA256}  ${STATIC_BIN}" > "${TARGETS_DIR}/static_elf_${RUN_ID}.sha256"
    echo "  -> Verified static ELF (SHA256: ${STATIC_ELF_SHA256})"

    # Setuid runner compilation and privileged permission configuration
    SETUID_RUNNER_PATH="${TARGETS_DIR}/setuid_runner_${RUN_ID}"
    gcc -O2 "${SETUID_SRC}" -o "${SETUID_RUNNER_PATH}"
    sudo chown root:root "${SETUID_RUNNER_PATH}"
    sudo chmod 4755 "${SETUID_RUNNER_PATH}"
    CREATED_SETUID_RUNNER="true"

    # Record launch-time metadata for setuid executable (mode, ownership, mount options, NoNewPrivs)
    SETUID_LAUNCH_STAT="${TARGETS_DIR}/setuid_launch_stat.json"
    MOUNT_OPTS=$(findmnt -n -o OPTIONS -T "${SETUID_RUNNER_PATH}" 2>/dev/null || echo "unknown")
    NO_NEW_PRIVS=$(grep -i "NoNewPrivs" /proc/self/status 2>/dev/null | awk '{print $2}' || echo "0")
    cat << EOF > "${SETUID_LAUNCH_STAT}"
{
  "target_path": "${SETUID_RUNNER_PATH}",
  "launch_stat_mode": "$(stat -c '%a' "${SETUID_RUNNER_PATH}")",
  "launch_stat_uid": $(stat -c '%u' "${SETUID_RUNNER_PATH}"),
  "launch_stat_gid": $(stat -c '%g' "${SETUID_RUNNER_PATH}"),
  "mount_options": "${MOUNT_OPTS}",
  "nosuid_mount": $(if [[ "${MOUNT_OPTS}" == *"nosuid"* ]]; then echo "true"; else echo "false"; fi),
  "process_no_new_privs": ${NO_NEW_PRIVS},
  "suid_transition_permitted": true
}
EOF
    echo "  -> Staged setuid runner and captured launch-time metadata"

    # Shebang script
    SHEBANG_PATH="${TARGETS_DIR}/shebang_${RUN_ID}.sh"
    cat << 'EOF' > "${SHEBANG_PATH}"
#!/bin/sh
exit 0
EOF
    chmod +x "${SHEBANG_PATH}"

    # Symlink target (portable relative symlink)
    (cd "${TARGETS_DIR}" && ln -sf target_std_execve "symlink_${RUN_ID}")
    echo "  -> Staged relative symlink -> target_std_execve"

    # EACCES target (permission 0644)
    EACCES_PATH="${TARGETS_DIR}/no_exec_${RUN_ID}.bin"
    touch "${EACCES_PATH}"
    chmod 0644 "${EACCES_PATH}"

    # ENOENT target (ensure absent)
    ENOENT_PATH="${TARGETS_DIR}/nonexistent_${RUN_ID}_xyz"
    rm -f "${ENOENT_PATH}"

    # Pathname truncation target: deeply nested directory path > 256 bytes with RUN_ID in first 200B
    PAD_BASE="${EVIDENCE_DIR}/pad_${RUN_ID}"
    PAD_DIR="${PAD_BASE}/d1_$(printf 'a%.0s' {1..50})/d2_$(printf 'b%.0s' {1..50})/d3_$(printf 'c%.0s' {1..50})"
    mkdir -p "${PAD_DIR}"
    cp "${TARGETS_DIR}/target_std_execve" "${PAD_DIR}/target_trunc"
    chmod +x "${PAD_DIR}/target_trunc"
    echo "${PAD_DIR}/target_trunc" > "${TARGETS_DIR}/path_trunc_marker.txt"
    LONG_PATH_LEN=$(echo -n "${PAD_DIR}/target_trunc" | wc -c)
    echo "  -> Staged pathname truncation target (Length: ${LONG_PATH_LEN} bytes)"

    # Record frozen SUT manifest and checksums in evidence directory
    cat << EOF > "${EVIDENCE_DIR}/frozen_sut_manifest.json"
{
  "repository": "https://github.com/ramKarthik57/containerguard",
  "base_branch": "master",
  "current_branch": "test/supervisor-and-migration-redesign",
  "milestone_tag": "milestone-50-percent-verified",
  "milestone_commit": "b8f70f5f614a8927278ea031ff9c338791c40f01",
  "frozen_artifacts": {
    "bin/containerguard": {
      "path": "bin/containerguard",
      "sha256": "cfee0d9675b653fdd7cda2629454a4839b1fd59ede0ba43f8bcd7ce7bebc93d0",
      "verified_match": $(if [[ "$(sha256sum "${ROOT_DIR}/bin/containerguard" | awk '{print $1}')" == "cfee0d9675b653fdd7cda2629454a4839b1fd59ede0ba43f8bcd7ce7bebc93d0" ]]; then echo "true"; else echo "false"; fi)
    },
    "bpf/execve_events.o": {
      "path": "bpf/execve_events.o",
      "sha256": "6ae519a012694f11c9ab514c1b13cafb4b8551fb8deadaf10dee817862717ef3",
      "verified_match": $(if [[ "$(sha256sum "${ROOT_DIR}/bpf/execve_events.o" | awk '{print $1}')" == "6ae519a012694f11c9ab514c1b13cafb4b8551fb8deadaf10dee817862717ef3" ]]; then echo "true"; else echo "false"; fi)
    },
    "bin/test_exec_paths": {
      "path": "bin/test_exec_paths",
      "sha256": "37890b6bbc638c6066609afbd2cc98cfcb3ca70cd996385a44e4728f1459a32f",
      "verified_match": $(if [[ "$(sha256sum "${ROOT_DIR}/bin/test_exec_paths" | awk '{print $1}')" == "37890b6bbc638c6066609afbd2cc98cfcb3ca70cd996385a44e4728f1459a32f" ]]; then echo "true"; else echo "false"; fi)
    },
    "bin/cg_setuid_test": {
      "path": "bin/cg_setuid_test",
      "sha256": "b11b8709bfa3e4038ecfe7705500c9733be248e168af7991ae6e170c01596a95",
      "verified_match": $(if [[ "$(sha256sum "${ROOT_DIR}/bin/cg_setuid_test" | awk '{print $1}')" == "b11b8709bfa3e4038ecfe7705500c9733be248e168af7991ae6e170c01596a95" ]]; then echo "true"; else echo "false"; fi)
    }
  }
}
EOF

    # Pre-create FIFOs for runner-supervisor synchronization
    RELEASE_FIFO="${EVIDENCE_DIR}/supervisor_release.fifo"
    CMD_FIFO="${EVIDENCE_DIR}/mig_cmd.fifo"
    RESP_FIFO="${EVIDENCE_DIR}/mig_resp.fifo"
    rm -f "${RELEASE_FIFO}" "${CMD_FIFO}" "${RESP_FIFO}"
    mkfifo "${RELEASE_FIFO}" "${CMD_FIFO}" "${RESP_FIFO}"

    # -------------------------------------------------------------
    # 3. Start ContainerGuard Daemon
    # -------------------------------------------------------------
    echo "[3/6] Starting ContainerGuard daemon..."
    sudo "${ROOT_DIR}/bin/containerguard" \
        -bpf "${ROOT_DIR}/bpf/execve_events.o" \
        -events-log "${EVENTS_LOG}" \
        -alerts-log "${ALERTS_LOG}" \
        -metrics-interval 1s > "${DAEMON_LOG}" 2>&1 &
    DAEMON_PID=$!

    # Wait for BPF programs to load and attach
    sleep 1.0

    if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
        echo "Error: ContainerGuard daemon failed to start or exited prematurely." >&2
        if [[ -f "${DAEMON_LOG}" ]]; then
            cat "${DAEMON_LOG}" >&2
        fi
        exit 1
    fi
    echo "[+] ContainerGuard active with PID ${DAEMON_PID}"

    # -------------------------------------------------------------
    # 4. Dispatch Supervisor & Manage Cgroup Migration Handshake
    # -------------------------------------------------------------
    echo "[4/6] Launching test supervisor and executing workloads..."

    # Launch supervisor in background
    "${BUILD_DIR}/supervisor" "${EVIDENCE_DIR}" "${RUN_ID}" > "${EVIDENCE_DIR}/supervisor.log" 2>&1 &
    SUPERVISOR_JOB_PID=$!

    # Discover supervisor execution event in telemetry to establish Anchor G
    ANCHOR_G=""
    echo "  -> Waiting for supervisor execution event to establish Anchor G..."
    for i in {1..50}; do
        if [[ -f "${EVENTS_LOG}" ]]; then
            ANCHOR_G=$(python3 -c '
import json, sys
events_log = sys.argv[1]
with open(events_log) as f:
    for line in f:
        try:
            e = json.loads(line)
            fn = e.get("filename", "")
            if fn.endswith("/supervisor") or fn == "supervisor":
                print(e.get("tgid"))
                sys.exit(0)
        except Exception:
            pass
sys.exit(1)
' "${EVENTS_LOG}" 2>/dev/null || true)
            if [[ -n "${ANCHOR_G}" ]]; then
                break
            fi
        fi
        sleep 0.1
    done

    if [[ -z "${ANCHOR_G}" ]]; then
        echo "Error: Failed to discover supervisor execution event in telemetry within 5 seconds!" >&2
        exit 1
    fi
    echo "[+] Established supervisor Anchor TGID G = ${ANCHOR_G}"

    # Release supervisor to dispatch scenarios
    echo "GO" > "${RELEASE_FIFO}"

    # Service cgroup migration handshakes from supervisor
    echo "  -> Servicing cgroup migration handshake protocol..."

    # Command 1: PLACE_CG1 <child_pid>
    CMD1=""
    CHILD_PID1=""
    if ! read -t 15 -r CMD1 CHILD_PID1 < "${CMD_FIFO}"; then
        echo "Error: Timeout waiting for PLACE_CG1 command from supervisor!" >&2
        exit 1
    fi
    if [[ "${CMD1}" != "PLACE_CG1" || -z "${CHILD_PID1}" ]]; then
        echo "Error: Expected PLACE_CG1 <pid>, got '${CMD1} ${CHILD_PID1}'" >&2
        exit 1
    fi
    echo "  [cgroup] Placing fork-only child ${CHILD_PID1} into CG1 (inode: ${CG1_INODE})..."
    echo "${CHILD_PID1}" | sudo tee "${MIG_GRP1}/cgroup.procs" > /dev/null
    if ! sudo grep -q "^${CHILD_PID1}$" "${MIG_GRP1}/cgroup.procs"; then
        echo "Error: Verification failed for child ${CHILD_PID1} in ${MIG_GRP1}/cgroup.procs" >&2
        exit 1
    fi
    echo "OK" > "${RESP_FIFO}"

    # Command 2: MIGRATE_CG2 <child_pid>
    CMD2=""
    CHILD_PID2=""
    if ! read -t 15 -r CMD2 CHILD_PID2 < "${CMD_FIFO}"; then
        echo "Error: Timeout waiting for MIGRATE_CG2 command from supervisor!" >&2
        exit 1
    fi
    if [[ "${CMD2}" != "MIGRATE_CG2" || -z "${CHILD_PID2}" ]]; then
        echo "Error: Expected MIGRATE_CG2 <pid>, got '${CMD2} ${CHILD_PID2}'" >&2
        exit 1
    fi

    # Barrier A: Verify mig_phase1 event is fully processed and committed to JSONL
    echo "  [barrier] Barrier A: Waiting for mig_phase1 event in telemetry..."
    PHASE1_FOUND="false"
    for i in {1..50}; do
        if grep -q "mig_phase1" "${EVENTS_LOG}" 2>/dev/null; then
            PHASE1_FOUND="true"
            break
        fi
        sleep 0.1
    done
    if [[ "${PHASE1_FOUND}" != "true" ]]; then
        echo "Error: Barrier A failure: mig_phase1 event not found in ${EVENTS_LOG}!" >&2
        exit 1
    fi
    echo "  [barrier] Barrier A satisfied: Phase 1 telemetry committed."

    # Migrate child to CG2 and verify
    echo "  [cgroup] Migrating child ${CHILD_PID2} into CG2 (inode: ${CG2_INODE})..."
    echo "${CHILD_PID2}" | sudo tee "${MIG_GRP2}/cgroup.procs" > /dev/null
    if ! sudo grep -q "^${CHILD_PID2}$" "${MIG_GRP2}/cgroup.procs"; then
        echo "Error: Verification failed for child ${CHILD_PID2} in ${MIG_GRP2}/cgroup.procs" >&2
        exit 1
    fi

    # Save detailed cgroup migration audit record
    cat << EOF > "${EVIDENCE_DIR}/cgroup_migration_audit.json"
{
  "cg1_path": "${MIG_GRP1}",
  "cg1_inode": ${CG1_INODE},
  "cg1_child_userspace_pid": ${CHILD_PID1},
  "cg1_placement_verified": true,
  "cg2_path": "${MIG_GRP2}",
  "cg2_inode": ${CG2_INODE},
  "cg2_child_userspace_pid": ${CHILD_PID2},
  "cg2_placement_verified": true,
  "migration_handshake_successful": true
}
EOF
    echo "OK" > "${RESP_FIFO}"

    # Wait for supervisor process to complete all scenarios
    echo "  -> Waiting for supervisor to complete remaining workloads..."
    if ! wait "${SUPERVISOR_JOB_PID}"; then
        echo "Error: Supervisor process exited with non-zero status!" >&2
        exit 1
    fi
    SUPERVISOR_JOB_PID=""
    echo "[+] Supervisor finished all scenarios successfully."

    # -------------------------------------------------------------
    # 5. Dispatch Containerized Executions & Teardown Daemon
    # -------------------------------------------------------------
    echo "[5/6] Dispatching containerized executions..."
    sudo docker exec cg-test-a /bin/date
    sudo docker exec cg-test-a /bin/echo "container A live workload"
    sudo docker exec cg-test-b-event-test /bin/uname -a

    # Clean up test cgroups created by this specific run
    if [[ "${CREATED_MIG_GRP1}" == "true" && -d "${MIG_GRP1}" ]]; then
        sudo rmdir "${MIG_GRP1}" 2>/dev/null || true
        CREATED_MIG_GRP1="false"
    fi
    if [[ "${CREATED_MIG_GRP2}" == "true" && -d "${MIG_GRP2}" ]]; then
        sudo rmdir "${MIG_GRP2}" 2>/dev/null || true
        CREATED_MIG_GRP2="false"
    fi

    # Clean up transient FIFOs so they are not included in evidence tarball
    rm -f "${RELEASE_FIFO}" "${CMD_FIFO}" "${RESP_FIFO}"

    sleep 1.0

    echo "Shutting down ContainerGuard daemon..."
    if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        sudo kill -TERM "${DAEMON_PID}" || true
        wait "${DAEMON_PID}" 2>/dev/null || true
        DAEMON_PID=""
    fi
    echo "[+] ContainerGuard stopped gracefully."
fi

# -------------------------------------------------------------
# 6. Evaluate and Compile Empirical Report
# -------------------------------------------------------------
echo "[6/6] Compiling Execution Path and Adversarial Telemetry Evaluation..."

python3 - "${EVIDENCE_DIR}" "${ARCHIVE_MODE}" << 'PYEOF'
import json
import os
import re
import sys

evidence_dir = sys.argv[1] if len(sys.argv) > 1 else "docs/evidence/phase_i"
archive_mode = (sys.argv[2].lower() == "true") if len(sys.argv) > 2 else False
events_log = os.path.join(evidence_dir, "exec_paths_events.jsonl")
daemon_log = os.path.join(evidence_dir, "exec_paths.log")
report_path = os.path.join(evidence_dir, "execution_path_report.json")
test_pids_path = os.path.join(evidence_dir, "test_pids.json")
supervisor_manifest_path = os.path.join(evidence_dir, "supervisor_manifest.json")
cgroup_audit_path = os.path.join(evidence_dir, "cgroup_migration_audit.json")

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

if not accounting:
    print(f"\n[!] ACCOUNTING FAILURE: No final telemetry accounting report found in {daemon_log}!")
    sys.exit(1)

REQUIRED_ACCOUNTING_FIELDS = [
    "kernel_hook_invocations",
    "kernel_ringbuf_reserve_drops",
    "kernel_ringbuf_submitted",
    "userspace_records_decoded",
    "userspace_decode_failures",
    "userspace_queue_overflows",
    "sequence_gaps_detected",
    "userspace_loss_count",
    "events_processed",
    "processing_failures",
]

missing_fields = [f for f in REQUIRED_ACCOUNTING_FIELDS if f not in accounting]
if missing_fields:
    print(f"\n[!] ACCOUNTING FAILURE: Telemetry report missing required fields: {missing_fields}")
    sys.exit(1)

hook_calls = accounting["kernel_hook_invocations"]
submitted = accounting["kernel_ringbuf_submitted"]
drops = accounting["kernel_ringbuf_reserve_drops"]
decoded = accounting["userspace_records_decoded"]
decode_failures = accounting["userspace_decode_failures"]
queue_overflows = accounting["userspace_queue_overflows"]
sequence_gaps = accounting["sequence_gaps_detected"]
userspace_loss = accounting["userspace_loss_count"]
processed = accounting["events_processed"]
proc_failures = accounting["processing_failures"]

# 1. Non-zero activity validation
if hook_calls <= 0 or submitted <= 0:
    print(f"\n[!] ACCOUNTING FAILURE: Zero hook invocations ({hook_calls}) or submissions ({submitted}) recorded!")
    sys.exit(1)

# 2. Conservation invariant: Hooks == Submissions + Drops
conservation_valid = (hook_calls == submitted + drops)
if not conservation_valid:
    print(f"\n[!] CONSERVATION VIOLATION: Hooks ({hook_calls}) != Submissions ({submitted}) + Drops ({drops})")
    sys.exit(1)

# 3. Explicit zero kernel drops: fail immediately if any kernel ring buffer drops occur
if drops != 0:
    print(f"\n[!] KERNEL EVENT LOSS: {drops} kernel ring buffer reserve drops recorded!")
    sys.exit(1)

# 4. Complete userspace delivery: reject any loss where decoded != submitted
if decoded != submitted:
    print(f"\n[!] INCOMPLETE TELEMETRY DELIVERY: Decoded ({decoded}) != Submissions ({submitted}) (Loss: {submitted - decoded})")
    sys.exit(1)

# 5. Zero decode failures
if decode_failures != 0:
    print(f"\n[!] DECODE FAILURE: {decode_failures} record decode failures!")
    sys.exit(1)

# 6. Zero queue overflows
if queue_overflows != 0:
    print(f"\n[!] QUEUE OVERFLOW: {queue_overflows} userspace queue overflows!")
    sys.exit(1)

# 7. Zero sequence gaps
if sequence_gaps != 0:
    print(f"\n[!] SEQUENCE INTEGRITY FAILURE: {sequence_gaps} sequence gaps detected!")
    sys.exit(1)

# 8. Zero userspace loss count
if userspace_loss != 0:
    print(f"\n[!] USERSPACE LOSS FAILURE: {userspace_loss} lost events accounted!")
    sys.exit(1)

# 9. Downstream pipeline processing agreement: processed == submitted
if processed != submitted:
    print(f"\n[!] PIPELINE PROCESSING MISMATCH: Processed ({processed}) != Submitted ({submitted})")
    sys.exit(1)

# 10. Zero processing failures
if proc_failures != 0:
    print(f"\n[!] PIPELINE PROCESSING FAILURE: {proc_failures} processing failures in daemon pipeline!")
    sys.exit(1)

# 11. Event log agreement: len(events) == processed
if len(events) != processed:
    print(f"\n[!] LOG FILE INCOMPLETE: Recorded events ({len(events)}) != Processed events ({processed})")
    sys.exit(1)

# Analyze observed execution features
execveat_count = sum(1 for e in events if e.get("execveat"))
at_empty_path_count = sum(1 for e in events if e.get("at_empty_path"))
path_truncated_count = sum(1 for e in events if e.get("path_truncated"))
comm_truncated_count = sum(1 for e in events if e.get("comm_truncated"))
failed_count = sum(1 for e in events if e.get("failed"))
committed_count = sum(1 for e in events if e.get("committed"))
cgroup_migrated_count = sum(1 for e in events if e.get("cgroup_migrated"))

coverage = {}
dispatched_pids = {}

if archive_mode:
    # Historical archive fallback
    test_tgids = []
    for e in events:
        tg = e.get("tgid")
        if "test_exec_paths" in e.get("filename", "") and tg not in test_tgids:
            test_tgids.append(tg)
    if len(test_tgids) < 10:
        print(f"\n[!] ARCHIVE EVALUATION FAILURE: Found only {len(test_tgids)} test TGIDs (expected at least 10)!")
        sys.exit(1)

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
        "static_elf": None,
        "setuid_transition": None,
        "cgroup_migration": 984,
    }

    coverage["standard_execve"] = any(e.get("tgid") == dispatched_pids["standard_execve"] and e.get("filename") == "/bin/true" and not e.get("execveat") and not e.get("cgroup_migrated") for e in events)
    coverage["direct_syscall_execve"] = any(e.get("tgid") == dispatched_pids["direct_syscall"] and e.get("filename") == "/bin/true" and not e.get("execveat") and not e.get("cgroup_migrated") for e in events)
    coverage["execveat_relative"] = any(e.get("tgid") == dispatched_pids["execveat_relative"] and e.get("execveat") and not e.get("at_empty_path") for e in events)
    coverage["execveat_at_empty_path_memfd"] = any(e.get("tgid") == dispatched_pids["execveat_memfd"] and e.get("execveat") and e.get("at_empty_path") for e in events)
    coverage["shebang_script"] = any(e.get("tgid") == dispatched_pids["shebang"] and "cg_test_shebang" in e.get("filename", "") for e in events)
    coverage["symlink_traversal"] = any(e.get("tgid") == dispatched_pids["symlink"] and "cg_test_symlink" in e.get("filename", "") for e in events)
    coverage["static_elf_binary"] = any("cg_static_test" in e.get("filename", "") for e in events)
    coverage["setuid_euid_transition"] = any(("cg_setuid_test" in e.get("filename", "") or "cg_setuid_runner" in e.get("filename", "")) and e.get("uid") != e.get("euid") and e.get("setuid_exec") and e.get("euid") == 0 for e in events)
    coverage["failed_exec_enoent"] = any(e.get("tgid") == dispatched_pids["fail_enoent"] and e.get("failed") and e.get("exit_code") == -2 for e in events)
    coverage["failed_exec_eacces"] = any(e.get("tgid") == dispatched_pids["fail_eacces"] and e.get("failed") and e.get("exit_code") == -13 for e in events)
    coverage["pathname_truncation"] = any(e.get("tgid") == dispatched_pids["path_truncation"] and e.get("path_truncated") for e in events)
    coverage["comm_truncation"] = any(e.get("tgid") == dispatched_pids["comm_truncation"] and e.get("comm_truncated") for e in events)
    coverage["container_workload_attribution"] = (
        any(e.get("attribution_state") == "RESOLVED" and e.get("container_name") == "cg-test-a" for e in events) and
        any(e.get("attribution_state") == "RESOLVED" and e.get("container_name") == "cg-test-b-event-test" for e in events)
    )
    coverage["cgroup_migration_tracking"] = any(e.get("tgid") == dispatched_pids["cgroup_migration"] and e.get("cgroup_migrated") for e in events)
else:
    # Live reproduction mode: Supervisor TGID Anchor & Semantic Disambiguation
    supervisor_event = None
    for e in events:
        fn = e.get("filename", "")
        if fn.endswith("/supervisor") or fn == "supervisor":
            supervisor_event = e
            break

    if not supervisor_event:
        print("\n[!] SUPERVISOR ANCHOR FAILURE: No supervisor execution event found in telemetry!")
        sys.exit(1)

    G = supervisor_event.get("tgid")
    print(f"[*] Discovered Supervisor Anchor TGID G = {G}")

    # Synchronize supervisor_manifest.json with discovered kernel TGID
    if os.path.exists(supervisor_manifest_path):
        try:
            with open(supervisor_manifest_path, "r") as mf:
                mdata = json.load(mf)
            mdata["supervisor_kernel_tgid"] = G
            with open(supervisor_manifest_path, "w") as mf:
                json.dump(mdata, mf, indent=2)
        except Exception:
            pass

    # 1. Standard execve
    std_ev = next((e for e in events if e.get("parent_tgid") == G and "target_std_execve" in e.get("filename", "")), None)
    coverage["standard_execve"] = bool(std_ev and not std_ev.get("execveat") and not std_ev.get("cgroup_migrated"))
    if std_ev: dispatched_pids["standard_execve"] = std_ev.get("tgid")

    # 2. Direct syscall (SYS_execve)
    direct_ev = next((e for e in events if e.get("parent_tgid") == G and "target_direct_syscall" in e.get("filename", "")), None)
    coverage["direct_syscall_execve"] = bool(direct_ev and not direct_ev.get("execveat") and not direct_ev.get("cgroup_migrated"))
    if direct_ev: dispatched_pids["direct_syscall"] = direct_ev.get("tgid")

    # 3. Relative execveat
    rel_ev = next((e for e in events if e.get("parent_tgid") == G and "relative_execveat" in e.get("filename", "")), None)
    coverage["execveat_relative"] = bool(rel_ev and rel_ev.get("execveat") and not rel_ev.get("at_empty_path"))
    if rel_ev: dispatched_pids["execveat_relative"] = rel_ev.get("tgid")

    # 4. memfd with AT_EMPTY_PATH
    memfd_ev = next((e for e in events if e.get("parent_tgid") == G and e.get("execveat") and e.get("at_empty_path")), None)
    coverage["execveat_at_empty_path_memfd"] = bool(memfd_ev and ("anon_elf" in memfd_ev.get("comm", "") or "anon_elf" in memfd_ev.get("filename", "")))
    if memfd_ev: dispatched_pids["execveat_memfd"] = memfd_ev.get("tgid")

    # 5. Shebang script
    shebang_ev = next((e for e in events if e.get("parent_tgid") == G and "shebang" in e.get("filename", "")), None)
    coverage["shebang_script"] = bool(shebang_ev)
    if shebang_ev: dispatched_pids["shebang"] = shebang_ev.get("tgid")

    # 6. Symlink traversal
    sym_ev = next((e for e in events if e.get("parent_tgid") == G and "symlink" in e.get("filename", "")), None)
    coverage["symlink_traversal"] = bool(sym_ev)
    if sym_ev: dispatched_pids["symlink"] = sym_ev.get("tgid")

    # 7. Static ELF binary
    static_ev = next((e for e in events if e.get("parent_tgid") == G and "static_elf" in e.get("filename", "")), None)
    coverage["static_elf_binary"] = bool(static_ev)
    if static_ev: dispatched_pids["static_elf"] = static_ev.get("tgid")

    # 8. Failed exec ENOENT
    enoent_ev = next((e for e in events if e.get("parent_tgid") == G and "nonexistent" in e.get("filename", "")), None)
    coverage["failed_exec_enoent"] = bool(enoent_ev and enoent_ev.get("failed") and enoent_ev.get("exit_code") == -2)
    if enoent_ev: dispatched_pids["fail_enoent"] = enoent_ev.get("tgid")

    # 9. Failed exec EACCES
    eacces_ev = next((e for e in events if e.get("parent_tgid") == G and "no_exec" in e.get("filename", "")), None)
    coverage["failed_exec_eacces"] = bool(eacces_ev and eacces_ev.get("failed") and eacces_ev.get("exit_code") == -13)
    if eacces_ev: dispatched_pids["fail_eacces"] = eacces_ev.get("tgid")

    # 10. Pathname truncation (> 256 bytes)
    path_trunc_ev = next((e for e in events if e.get("parent_tgid") == G and e.get("path_truncated") and ("pad_" in e.get("filename", "") or "target_trunc" in e.get("filename", ""))), None)
    coverage["pathname_truncation"] = bool(path_trunc_ev)
    if path_trunc_ev: dispatched_pids["path_truncation"] = path_trunc_ev.get("tgid")

    # 11. Comm truncation (ISOLATED: short basename target "comm_short")
    # Proves comm_truncated is triggered solely by pre-exec PR_SET_NAME (16B), not executable name.
    comm_trunc_ev = next((e for e in events if e.get("parent_tgid") == G and "comm_short" in e.get("filename", "") and e.get("comm_truncated")), None)
    coverage["comm_truncation"] = bool(comm_trunc_ev)
    if comm_trunc_ev: dispatched_pids["comm_truncation"] = comm_trunc_ev.get("tgid")

    # 12. Setuid EUID transition
    setuid_ev = next((e for e in events if e.get("parent_tgid") == G and "setuid_runner" in e.get("filename", "")), None)
    coverage["setuid_euid_transition"] = bool(
        setuid_ev
        and setuid_ev.get("setuid_exec")
        and setuid_ev.get("uid") != setuid_ev.get("euid")
        and setuid_ev.get("euid") == 0
    )
    if setuid_ev: dispatched_pids["setuid_transition"] = setuid_ev.get("tgid")

    # 13. Container workload attribution
    has_container_a = any(e.get("attribution_state") == "RESOLVED" and e.get("container_name") == "cg-test-a" for e in events)
    has_container_b = any(e.get("attribution_state") == "RESOLVED" and e.get("container_name") == "cg-test-b-event-test" for e in events)
    coverage["container_workload_attribution"] = (has_container_a and has_container_b)

    # 14. Cgroup migration (Fork-Only Bootstrap & Dual-Barrier Lineage Validation)
    mig_p1_ev = next((e for e in events if e.get("parent_tgid") == G and "mig_phase1" in e.get("filename", "")), None)
    mig_valid = False
    if mig_p1_ev:
        mig_tgid = mig_p1_ev.get("tgid")
        mig_start_time = mig_p1_ev.get("start_time_ns")
        dispatched_pids["cgroup_migration"] = mig_tgid

        prior_execs = [
            e for e in events
            if e.get("tgid") == mig_tgid
            and e.get("kernel_time_ns", 0) < mig_p1_ev.get("kernel_time_ns", 0)
        ]
        p1_is_first = (len(prior_execs) == 0)
        p1_not_migrated = (mig_p1_ev.get("cgroup_migrated") is False)

        mig_p2_ev = next((
            e for e in events
            if e.get("tgid") == mig_tgid
            and e.get("start_time_ns") == mig_start_time
            and "mig_phase2" in e.get("filename", "")
        ), None)

        p2_migrated = bool(
            mig_p2_ev
            and mig_p2_ev.get("cgroup_migrated") is True
            and mig_p2_ev.get("cgroup_id") != mig_p1_ev.get("cgroup_id")
        )

        mig_valid = (p1_is_first and p1_not_migrated and p2_migrated)
        if not mig_valid:
            print(f"[!] MIGRATION LINEAGE VALIDATION DETAILS:")
            print(f"    - mig_phase1 first exec for TGID: {p1_is_first} (prior execs: {len(prior_execs)})")
            print(f"    - mig_phase1 cgroup_migrated == false: {p1_not_migrated}")
            print(f"    - mig_phase2 present: {bool(mig_p2_ev)}")
            if mig_p2_ev:
                print(f"    - mig_phase2 cgroup_migrated == true: {mig_p2_ev.get('cgroup_migrated')}")
                print(f"    - cgroup_id transition: {mig_p1_ev.get('cgroup_id')} -> {mig_p2_ev.get('cgroup_id')}")

    coverage["cgroup_migration_tracking"] = mig_valid

    # Save dispatched_pids with explicit provenance note
    with open(test_pids_path, "w") as f:
        json.dump(dispatched_pids, f, indent=2)

delivery_rate_pct = (decoded / submitted * 100.0) if submitted > 0 else 0.0

resolved_count = sum(1 for e in events if e.get("attribution_state") == "RESOLVED")
unresolved_count = sum(1 for e in events if e.get("attribution_state") == "UNRESOLVED")

report = {
    "archive_mode": archive_mode,
    "evaluation_mode": (
        "historical_archive_fallback (11/14 TGID-correlated: 10 reconstructed execution-path TGIDs and the historical cgroup-migration TGID 984; 1/14 container-name matched; 2/14 event signatures)"
        if archive_mode else
        "live_reproduction_supervisor_anchor (Supervisor TGID G anchor, 12 scenario parentage assertions, isolated comm_short, fork-only dual-barrier migration)"
    ),
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
        "events_processed": processed,
        "processing_failures": proc_failures,
        "conservation_satisfied": conservation_valid,
        "zero_drops_satisfied": (drops == 0),
        "delivery_rate_percent": round(delivery_rate_pct, 4),
        "container_attribution_resolved": resolved_count,
        "host_workload_unresolved": unresolved_count
    },
    "execution_path_coverage": coverage,
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
    "dispatched_pids": dispatched_pids,
    "notes": {
        "persistence_order_note": "Monotonically increasing sequence numbers (0..N-1) are assigned in eBPF kernel ringbuffer. Minor non-monotonic line order in JSONL occurs due to asynchronous Docker container attribution queue processing in userspace pipeline.",
        "test_pids_provenance": "test_pids.json records the kernel TGIDs discovered from the telemetry event stream matching each supervisor-dispatched scenario.",
        "attribution_breakdown": f"{resolved_count} events resolved to Docker containers (cg-test-a, cg-test-b-event-test); {unresolved_count} events are host-side benchmark executions."
    }
}

if not archive_mode:
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
print(f" Events Processed by Pipeline:     {processed}")
print(f" Pipeline Processing Failures:     {proc_failures}")
print(f" Conservation (Hooks = Sub + Drop):{'PASS' if conservation_valid else 'FAIL'}")
print(f" Zero Drops Invariant:             {'PASS' if drops == 0 else 'FAIL'}")
print(f" Telemetry Delivery Rate:          {delivery_rate_pct:.2f}%")
print(f" Attribution Breakdown:            {resolved_count} Container-Resolved / {unresolved_count} Host Workloads")
print("-" * 65)
if archive_mode:
    print(" Execution Path Coverage (Archive Evaluation: 11 TGID-correlated [10 reconstructed + TGID 984], 1 Container-name matched, 2 Signature):")
else:
    print(" Execution Path Coverage (Live Reproduction: Supervisor Anchor G + Semantic Telemetry):")
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

if [[ "${ARCHIVE_MODE}" == "true" ]]; then
    echo "[+] Phase I archive evaluation finished. Historical evidence evaluated without modification."
else
    echo "[+] Phase I execution-path benchmark finished. Report saved to ${REPORT_JSON}."
fi
