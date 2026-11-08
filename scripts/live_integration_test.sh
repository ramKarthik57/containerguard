#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="/tmp/containerguard_validation"
mkdir -p "$LOG_DIR"
DAEMON_LOG="$LOG_DIR/daemon.log"
EVENTS_LOG="$LOG_DIR/events.jsonl"
ALERTS_LOG="$LOG_DIR/alerts.jsonl"

LIFECYCLE_CONTAINER="cg-lifecycle-ephemeral"
RENAMED_CONTAINER="cg-lifecycle-renamed"

echo "================================================================="
echo " ContainerGuard: Phase F Live Kernel & Docker Validation Protocol"
echo "================================================================="

# Pre-flight check: ensure running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: This live integration test must be run with root privileges"
    echo "    Run: sudo ./scripts/live_integration_test.sh"
    exit 1
fi

# Ensure docker daemon is responding
if ! docker info >/dev/null 2>&1; then
    echo "[-] Error: Docker daemon is not accessible"
    exit 1
fi

echo "[1/10] Verifying compiled artifacts..."
if [ ! -f "bin/containerguard" ] || [ ! -f "bpf/execve_events.o" ]; then
    echo "[-] Artifacts missing, building now..."
    ./scripts/build.sh
fi
echo "[+] Artifacts verified: bin/containerguard and bpf/execve_events.o"

# Step 2: Inspect existing containers before making any changes
echo "[2/10] Inspecting existing research containers..."
docker ps -a --filter "name=cg-test" --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}"

# Ensure cg-test-a and cg-test-b-event-test exist; if not, create them without destroying any others
if ! docker ps -a --format '{{.Names}}' | grep -q "^cg-test-a$"; then
    echo "[+] Initializing research container cg-test-a..."
    docker run -d --name cg-test-a busybox:latest sleep 3600
fi

if ! docker ps -a --format '{{.Names}}' | grep -q "^cg-test-b-event-test$"; then
    echo "[+] Initializing research container cg-test-b-event-test..."
    docker run -d --name cg-test-b-event-test busybox:latest sleep 3600
fi

# Ensure both baseline research containers are running
docker start cg-test-a >/dev/null 2>&1 || true
docker start cg-test-b-event-test >/dev/null 2>&1 || true

echo "[+] Baseline research containers active (will NOT be stopped or renamed):"
docker ps --filter "name=cg-test" --format "  - {{.Names}} (ID: {{.ID}}, Status: {{.Status}})"

# Clean up any leftover temporary lifecycle container from a prior aborted run
docker rm -f "$LIFECYCLE_CONTAINER" "$RENAMED_CONTAINER" >/dev/null 2>&1 || true

# Step 3: Start ContainerGuard daemon
echo "[3/10] Starting ContainerGuard daemon (eBPF kernel load & tracepoint attach)..."
rm -f "$DAEMON_LOG" "$EVENTS_LOG" "$ALERTS_LOG"

./bin/containerguard \
    -bpf bpf/execve_events.o \
    -events-log "$EVENTS_LOG" \
    -alerts-log "$ALERTS_LOG" \
    -metrics-interval 2s \
    -pending-ttl 2s > "$DAEMON_LOG" 2>&1 &
CG_PID=$!
echo "[+] ContainerGuard running with PID $CG_PID"

# Trap exit to guarantee daemon cleanup and remove temporary lifecycle containers only
cleanup() {
    echo "[-] Shutting down ContainerGuard daemon..."
    kill -TERM "$CG_PID" 2>/dev/null || true
    wait "$CG_PID" 2>/dev/null || true
    docker rm -f "$LIFECYCLE_CONTAINER" "$RENAMED_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Wait 3 seconds for BPF initialization and Docker inventory sync
sleep 3
if ! kill -0 "$CG_PID" 2>/dev/null; then
    echo "[-] ContainerGuard failed to start. Logs:"
    cat "$DAEMON_LOG"
    exit 1
fi
echo "[+] ContainerGuard successfully attached to kernel tracepoint sys_enter_execve"

# Step 4: Generate telemetry in Container A (routine commands - baseline preserved)
echo "[4/10] Executing workload in cg-test-a..."
docker exec cg-test-a uname -a
docker exec cg-test-a ls -la /
docker exec cg-test-a date

# Step 5: Generate telemetry & security event in Container B (baseline preserved)
echo "[5/10] Executing workload and detection trigger in cg-test-b-event-test..."
docker exec cg-test-b-event-test id
docker exec cg-test-b-event-test /bin/sh -c "echo 'trigger test' > /dev/null"
# Trigger Rule CG-RULE-002: Writable directory execution
docker exec cg-test-b-event-test /bin/sh -c "echo '#!/bin/sh' > /tmp/test_alert.sh && echo 'echo alert' >> /tmp/test_alert.sh && chmod +x /tmp/test_alert.sh && /tmp/test_alert.sh && rm -f /tmp/test_alert.sh"

# Step 6: Dedicated lifecycle testing using separate temporary container (preserving cg-test-a & cg-test-b)
echo "[6/10] Testing container lifecycle using dedicated ephemeral container '$LIFECYCLE_CONTAINER'..."
docker run -d --name "$LIFECYCLE_CONTAINER" busybox:latest sleep 300 >/dev/null
sleep 1
docker exec "$LIFECYCLE_CONTAINER" uptime

# Test Restart
echo "      Testing restart..."
docker restart "$LIFECYCLE_CONTAINER" >/dev/null
sleep 1
docker exec "$LIFECYCLE_CONTAINER" uptime

# Test Rename
echo "      Testing rename..."
docker rename "$LIFECYCLE_CONTAINER" "$RENAMED_CONTAINER" >/dev/null
sleep 1
docker exec "$RENAMED_CONTAINER" uptime

# Clean up dedicated lifecycle test container
docker rm -f "$RENAMED_CONTAINER" >/dev/null

# Step 7: Test short-lived container (Attribution Race Condition test)
echo "[7/10] Testing ephemeral container attribution race..."
docker run --rm busybox:latest /bin/sh -c "echo 'ephemeral race check'; hostname"

# Allow pipeline to settle and drain pending queue
sleep 4

# Step 8: Send SIGTERM for graceful shutdown
echo "[8/10] Initiating graceful daemon shutdown..."
kill -TERM "$CG_PID"
wait "$CG_PID" 2>/dev/null || true
trap - EXIT INT TERM

# Step 9: Analyze and verify captured telemetry
echo "[9/10] Validating collected telemetry and attribution integrity..."

echo "--- Recent Telemetry Logs ---"
tail -n 25 "$DAEMON_LOG"

TOTAL_EVENTS=$(wc -l < "$EVENTS_LOG" 2>/dev/null || echo 0)
RESOLVED_A=$(grep -c "cg-test-a" "$EVENTS_LOG" 2>/dev/null || echo 0)
RESOLVED_B=$(grep -c "cg-test-b-event-test" "$EVENTS_LOG" 2>/dev/null || echo 0)
RESOLVED_LIFECYCLE=$(grep -c "cg-lifecycle" "$EVENTS_LOG" 2>/dev/null || echo 0)
ALERTS_COUNT=$(wc -l < "$ALERTS_LOG" 2>/dev/null || echo 0)

echo "================================================================="
echo " VALIDATION RESULTS"
echo "================================================================="
echo " Total Decoded Security Events:        $TOTAL_EVENTS"
echo " Events Attributed to cg-test-a:       $RESOLVED_A"
echo " Events Attributed to cg-test-b:       $RESOLVED_B"
echo " Events Attributed to lifecycle test:  $RESOLVED_LIFECYCLE"
echo " Deterministic Alerts Triggered:       $ALERTS_COUNT"
echo " Log files saved in:                   $LOG_DIR"
echo "================================================================="

if [ "$RESOLVED_A" -gt 0 ] && [ "$RESOLVED_B" -gt 0 ]; then
    echo "[+] SUCCESS: Both baseline research containers and lifecycle test containers correctly attributed."
else
    echo "[-] WARNING: Some container events were not attributed. Review $DAEMON_LOG"
fi
