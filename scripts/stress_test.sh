#!/usr/bin/env bash
set -euo pipefail

WORKLOAD_TARGET="${1:-1000}"
STRESS_DIR="/tmp/cg_stress_$WORKLOAD_TARGET"
rm -rf "$STRESS_DIR"
mkdir -p "$STRESS_DIR"

DAEMON_LOG="$STRESS_DIR/daemon.log"
EVENTS_LOG="$STRESS_DIR/events.jsonl"
ALERTS_LOG="$STRESS_DIR/alerts.jsonl"
REPORT_JSON="$STRESS_DIR/report.json"

TEMP_CONTAINER="cg-stress-worker"

echo "================================================================="
echo " ContainerGuard Phase H: Controlled Telemetry Stress Test"
echo " Target Workload: $WORKLOAD_TARGET events"
echo "================================================================="

# Pre-flight check: ensure running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: Stress test must be executed with root privileges"
    echo "    Run: sudo ./scripts/stress_test.sh $WORKLOAD_TARGET"
    exit 1
fi

# Ensure docker daemon is responding
if ! docker info >/dev/null 2>&1; then
    echo "[-] Error: Docker daemon is not accessible"
    exit 1
fi

# Ensure baseline containers are running
docker start cg-test-a >/dev/null 2>&1 || true
docker start cg-test-b-event-test >/dev/null 2>&1 || true

# Clean up any leftover temp worker from prior run
docker rm -f "$TEMP_CONTAINER" >/dev/null 2>&1 || true

# Start dedicated temporary worker container
docker run -d --name "$TEMP_CONTAINER" busybox:latest sleep 1800 >/dev/null

echo "[1/6] Starting ContainerGuard daemon..."
./bin/containerguard \
    -bpf bpf/execve_events.o \
    -events-log "$EVENTS_LOG" \
    -alerts-log "$ALERTS_LOG" \
    -metrics-interval 2s \
    -pending-ttl 2s > "$DAEMON_LOG" 2>&1 &
CG_PID=$!

cleanup() {
    kill -TERM "$CG_PID" 2>/dev/null || true
    wait "$CG_PID" 2>/dev/null || true
    docker rm -f "$TEMP_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

sleep 2
if ! kill -0 "$CG_PID" 2>/dev/null; then
    echo "[-] ContainerGuard failed to start. Logs:"
    cat "$DAEMON_LOG"
    exit 1
fi
echo "[+] ContainerGuard active with PID $CG_PID"

# Calculate distribution: 4 concurrent streams
N_WORKER=$(( WORKLOAD_TARGET / 4 ))
EXPECTED_TOTAL=$(( N_WORKER * 4 ))
echo "[2/6] Dispatching $EXPECTED_TOTAL concurrent events across 4 execution streams ($N_WORKER each)..."

T_START=$(date +%s.%N)

# Stream 1: cg-test-a
docker exec cg-test-a /bin/sh -c "for i in \$(seq 1 $N_WORKER); do /bin/true; done" &
PID1=$!

# Stream 2: cg-test-b-event-test (runs routine loop, plus 1 critical trigger)
docker exec cg-test-b-event-test /bin/sh -c "for i in \$(seq 1 $N_WORKER); do /bin/true; done; echo '#!/bin/sh' > /tmp/exploit_sim.sh && chmod +x /tmp/exploit_sim.sh && /tmp/exploit_sim.sh && rm -f /tmp/exploit_sim.sh" &
PID2=$!

# Stream 3: dedicated temp container cg-stress-worker
docker exec "$TEMP_CONTAINER" /bin/sh -c "for i in \$(seq 1 $N_WORKER); do /bin/true; done" &
PID3=$!

# Stream 4: host execution stream
/bin/sh -c "for i in \$(seq 1 $N_WORKER); do /bin/true; done" &
PID4=$!

echo "[3/6] Awaiting completion of all concurrent event streams..."
wait "$PID1"
wait "$PID2"
wait "$PID3"
wait "$PID4"

T_END=$(date +%s.%N)
ELAPSED=$(echo "$T_END - $T_START" | bc)
echo "[+] All worker streams finished in ${ELAPSED}s"

# Settle pipeline
sleep 2

# Stop ContainerGuard
echo "[4/6] Shutting down ContainerGuard daemon..."
kill -TERM "$CG_PID"
wait "$CG_PID" 2>/dev/null || true
trap - EXIT INT TERM

# Clean up dedicated temp container
docker rm -f "$TEMP_CONTAINER" >/dev/null 2>&1 || true

echo "[5/6] Extracting final telemetry integrity accounting..."
# Extract the JSON block from daemon.log
sed -n '/=== FINAL TELEMETRY INTEGRITY ACCOUNTING REPORT ===/,$p' "$DAEMON_LOG" | tail -n +2 > "$REPORT_JSON"

echo "[6/6] Compiling Performance and Integrity Evaluation..."

python3 - <<PYEOF
import json

with open("$REPORT_JSON") as f:
    data = json.load(f)

hooks = data.get("kernel_hook_invocations", 0)
submits = data.get("kernel_ringbuf_submitted", 0)
drops = data.get("kernel_ringbuf_reserve_drops", 0)
received = data.get("userspace_records_received", 0)
decoded = data.get("userspace_records_decoded", 0)
decode_fails = data.get("userspace_decode_failures", 0)
seq_gaps = data.get("sequence_gaps_detected", 0)
reordered = data.get("reordered_events", 0)
resolved = data.get("attribution_resolved", 0)
unresolved = data.get("attribution_unresolved", 0)
elapsed = float("$ELAPSED")

delivery_rate = (received / hooks * 100.0) if hooks > 0 else 0.0
throughput = hooks / elapsed if elapsed > 0 else 0.0

# Critical Invariant Verification:
# 1. Hook Invocations = Successful Submissions + Reservation Failures
if hooks != (submits + drops):
    print(f"\n[!] INVARIANT VIOLATION: Hooks ({hooks}) != Submits ({submits}) + Drops ({drops})")
    sys.exit(1)

# 2. Decoded records must never exceed submitted records
if decoded > submits:
    print(f"\n[!] BENCHMARK INVALIDATED: Decoded records ({decoded}) > submissions ({submits})!")
    sys.exit(1)

print("=================================================================")
print(" STRESS TEST EMPIRICAL EVALUATION SUMMARY")
print("=================================================================")
print(f" Target Event Count:                $WORKLOAD_TARGET")
print(f" Expected Worker Event Count:       $EXPECTED_TOTAL")
print(f" Observed Kernel Hook Calls:        {hooks}")
print(f" Ring Buffer Submissions:           {submits}")
print(f" Ring Buffer Reservation Drops:     {drops}")
print(f" Userspace Records Received:        {received}")
print(f" Userspace Records Decoded:         {decoded}")
print(f" Decode Failures:                   {decode_fails}")
print(f" Sequence Gaps Detected:            {seq_gaps}")
print(f" Reordered Events Handled:          {reordered}")
print(f" Attribution Resolved (Containers): {resolved}")
print(f" Attribution Unresolved (Non-Cont): {unresolved}")
print(f" Elapsed Workload Time:             {elapsed:.2f} seconds")
print(f" Measured Event Throughput:         {throughput:.1f} events/sec")
print(f" Telemetry Delivery Rate:           {delivery_rate:.2f}%")
print("=================================================================")
PYEOF
