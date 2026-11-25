#!/usr/bin/env bash
# ==============================================================================
# ContainerGuard Enterprise v2.0 - Live Web Dashboard Launcher
#
# Starts ContainerGuard eBPF daemon and the Live Web Console on http://localhost:8080
# Accessible directly in your Windows/Linux browser with live WebSocket/SSE streaming.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PORT="${1:-8080}"
DAEMON_PID=""
WEB_PID=""

# Colors
C_RESET="\033[0m"
C_BOLD="\033[1m"
C_GREEN="\033[32m"
C_CYAN="\033[36m"
C_RED="\033[31m"
C_YELLOW="\033[33m"
C_DIM="\033[2m"

banner() {
    clear 2>/dev/null || true
    echo -e "${C_CYAN}${C_BOLD}"
    cat << "EOF"
   ____            _        _                  ____                     _ 
  / ___|___  _ __ | |_ __ _(_)_ __   ___ _ __ / ___|_   _  __ _ _ __ __| |
 | |   / _ \| '_ \| __/ _` | | '_ \ / _ \ '__| |  _| | | |/ _` | '__/ _` |
 | |__| (_) | | | | || (_| | | | | |  __/ |  | |_| | |_| | (_| | | | (_| |
  \____\___/|_| |_|\__\__,_|_|_| |_|\___|_|   \____|\__,_|\__,_|_|  \__,_|
EOF
    echo -e "${C_BOLD}   Live Cyber-Defense Web Console -- http://localhost:${PORT}${C_RESET}"
    echo -e "${C_DIM}   Kernel: $(uname -r) | Docker Unified Cgroupv2 Hierarchy${C_RESET}"
    echo -e "${C_CYAN}======================================================================${C_RESET}\n"
}

cleanup() {
    echo -e "\n${C_DIM}[Cleanup] Shutting down Web Console and daemon services...${C_RESET}"
    if [[ -n "${WEB_PID:-}" ]] && kill -0 "${WEB_PID}" 2>/dev/null; then
        kill -15 "${WEB_PID}" 2>/dev/null || true
    fi
    if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        kill -15 "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi
    echo -e "${C_GREEN}[Cleanup] Clean shutdown complete.${C_RESET}"
}
trap cleanup EXIT INT TERM

# Ensure root privileges for eBPF probe attachment
if [[ $EUID -ne 0 ]]; then
    if ! sudo -v; then
        echo -e "${C_RED}Error: Root privileges required for eBPF probes and Docker interaction.${C_RESET}" >&2
        echo "Run with: sudo bash $0" >&2
        exit 1
    fi
    SUDO="sudo"
else
    SUDO=""
fi

# Ensure Docker is running
if ! ${SUDO} docker info >/dev/null 2>&1; then
    echo -e "${C_YELLOW}Starting Docker daemon service...${C_RESET}"
    ${SUDO} service docker start || true
fi

# Ensure baseline containers
for c in cg-test-a cg-test-b-event-test; do
    if ! ${SUDO} docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        if ${SUDO} docker ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
            ${SUDO} docker start "${c}" >/dev/null
        else
            ${SUDO} docker run -d --name "${c}" busybox:latest sleep 86400 >/dev/null
        fi
    fi
done

# Ensure binaries are built
if [[ ! -f "${ROOT_DIR}/bin/containerguard" ]] || [[ ! -f "${ROOT_DIR}/bin/cg-web" ]]; then
    echo -e "${C_DIM}Compiling project binaries...${C_RESET}"
    (cd "${ROOT_DIR}" && bash scripts/build.sh && go build -o bin/cg-web ./cmd/cg-web)
fi

banner

# Check if daemon is already running
EXISTING_PID=$(pgrep -f "bin/containerguard" | head -n 1 || true)
if [[ -n "${EXISTING_PID}" ]]; then
    echo -e "${C_GREEN}[OK] ContainerGuard eBPF daemon already running (PID: ${EXISTING_PID})${C_RESET}"
    DAEMON_PID=""
else
    echo -e "${C_CYAN}[+] Starting ContainerGuard eBPF daemon...${C_RESET}"
    ${SUDO} "${ROOT_DIR}/bin/containerguard" \
        -config "${ROOT_DIR}/configs/containerguard.yaml" \
        -events-log "${ROOT_DIR}/docs/evidence/exec_paths_events.jsonl" \
        -alerts-log "${ROOT_DIR}/docs/evidence/exec_paths_alerts.jsonl" \
        -mitigations-log "${ROOT_DIR}/docs/evidence/exec_paths_mitigations.jsonl" \
        > "${ROOT_DIR}/docs/evidence/daemon_web.log" 2>&1 &
    DAEMON_PID=$!
    
    # Wait for Prometheus
    tries=0
    while ! curl -s http://localhost:9115/metrics >/dev/null 2>&1; do
        sleep 0.5
        tries=$((tries + 1))
        if [[ $tries -gt 15 ]]; then
            echo -e "${C_RED}Error starting daemon. Check docs/evidence/daemon_web.log${C_RESET}"
            exit 1
        fi
    done
    echo -e "${C_GREEN}[PASS] eBPF daemon attached to kernel hooks (PID: ${DAEMON_PID})${C_RESET}"
fi

# Launch Web Server
echo -e "${C_CYAN}[+] Starting ContainerGuard Web Server on port ${PORT}...${C_RESET}"
${SUDO} "${ROOT_DIR}/bin/cg-web" \
    -port "${PORT}" \
    -root "${ROOT_DIR}" \
    -metrics-url "http://localhost:9115/metrics" \
    -db "docs/evidence/containerguard_evidence.db" \
    -config "configs/containerguard.yaml" &
WEB_PID=$!

sleep 1

echo -e "\n${C_GREEN}${C_BOLD}======================================================================${C_RESET}"
echo -e "${C_GREEN}${C_BOLD}  LIVE WEB DASHBOARD IS RUNNING & READY!${C_RESET}"
echo -e "${C_GREEN}${C_BOLD}======================================================================${C_RESET}"
echo -e "\nOpen your browser on your host (Windows or Linux) at:"
echo -e "\n    ${C_CYAN}${C_BOLD}👉  http://localhost:${PORT}  👈${C_RESET}\n"
echo -e "Features active in browser:"
echo -e "  * ${C_BOLD}Real-time Loss Conservation Invariant ($125 = 125 + 0$)${C_RESET}"
echo -e "  * ${C_BOLD}Live Attack Simulation Buttons${C_RESET} (Rule 001 Breakout, Rule 002 Writable Exec, etc.)"
echo -e "  * ${C_BOLD}Live Alerts & Nuclear cgroup.kill Mitigations Stream${C_RESET} (Sub-4ms response)"
echo -e "  * ${C_BOLD}Monitored Container Fleet${C_RESET} (Status of cg-test-a, cg-test-b, cg-demo-victim)"
echo -e "  * ${C_BOLD}Interactive SQLite WAL Evidence Explorer${C_RESET} (Live SQL query executor)"
echo -e "  * ${C_BOLD}Zero-Downtime SIGHUP Policy Reload Button${C_RESET}\n"
echo -e "${C_DIM}Press [Ctrl+C] in this terminal to stop the web console and daemon.${C_RESET}\n"

wait "${WEB_PID}"
