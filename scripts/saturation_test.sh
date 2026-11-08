#!/usr/bin/env bash
set -euo pipefail

LABEL="${1:-sat_default}"
RINGBUF_KB="${2:-16384}"
PAUSE_SEC="${3:-0}"
NUM_STREAMS="${4:-4}"
EVENTS_PER_STREAM="${5:-500}"

TOTAL_TARGET=$(( NUM_STREAMS * EVENTS_PER_STREAM ))
SAT_DIR="/tmp/cg_sat_$LABEL"
rm -rf "$SAT_DIR"
mkdir -p "$SAT_DIR"

DAEMON_LOG="$SAT_DIR/daemon.log"
EVENTS_LOG="$SAT_DIR/events.jsonl"
ALERTS_LOG="$SAT_DIR/alerts.jsonl"
REPORT_JSON="$SAT_DIR/report.json"
RESOURCE_LOG="$SAT_DIR/resource.log"

echo "================================================================="
echo " ContainerGuard Phase H.2: Controlled Saturation Evaluation"
echo " Benchmark Label:          $LABEL"
echo " Ring Buffer Size:         ${RINGBUF_KB} KiB"
echo " Backpressure Pause:       ${PAUSE_SEC} seconds"
echo " Concurrency Streams:      $NUM_STREAMS"
echo " Events per Stream:        $EVENTS_PER_STREAM"
echo " Target Workload Events:   $TOTAL_TARGET"
echo "================================================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: Saturation test must be executed with root privileges"
    echo "    Run: sudo ./scripts/saturation_test.sh $LABEL $RINGBUF_KB $PAUSE_SEC $NUM_STREAMS $EVENTS_PER_STREAM"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "[-] Error: Docker daemon is not accessible"
    exit 1
fi

# Ensure baseline containers remain running
docker start cg-test-a >/dev/null 2>&1 || true
docker start cg-test-b-event-test >/dev/null 2>&1 || true

# Prepare dedicated worker containers
TEMP_CONTAINERS=()
for i in $(seq 1 "$NUM_STREAMS"); do
    CNAME="cg-sat-worker-$i"
    docker rm -f "$CNAME" >/dev/null 2>&1 || true
    docker run -d --name "$CNAME" busybox:latest sleep 1800 >/dev/null
    TEMP_CONTAINERS+=("$CNAME")
done

cleanup() {
    kill -TERM "$CG_PID" 2>/dev/null || true
    wait "$CG_PID" 2>/dev/null || true
    for c in "${TEMP_CONTAINERS[@]}"; do
        docker rm -f "$c" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT INT TERM

echo "[1/6] Launching ContainerGuard daemon (RB: ${RINGBUF_KB} KiB, Pause: ${PAUSE_SEC}s)..."
./bin/containerguard \
    -bpf bpf/execve_events.o \
    -events-log "$EVENTS_LOG" \
    -alerts-log "$ALERTS_LOG" \
    -ringbuf-size-kb "$RINGBUF_KB" \
    -backpressure-pause-sec "$PAUSE_SEC" \
    -metrics-interval 1s \
    -pending-ttl 2s > "$DAEMON_LOG" 2>&1 &
CG_PID=$!

sleep 2
if ! kill -0 "$CG_PID" 2>/dev/null; then
    echo "[-] ContainerGuard failed to start. Logs:"
    cat "$DAEMON_LOG"
    exit 1
fi
echo "[+] ContainerGuard active with PID $CG_PID"

# Background resource sampler
(
    while kill -0 "$CG_PID" 2>/dev/null; do
        ps -p "$CG_PID" -o %cpu,rss,vsz --no-headers 2>/dev/null >> "$RESOURCE_LOG" || true
        sleep 0.2
    done
) &
SAMPLER_PID=$!

echo "[2/6] Dispatching $TOTAL_TARGET events across $NUM_STREAMS worker streams..."
T_START=$(date +%s.%N)

PIDS=()
for i in $(seq 1 "$NUM_STREAMS"); do
    CNAME="${TEMP_CONTAINERS[$((i - 1))]}"
    # Each container stream executes rapid true commands; stream 1 also includes one test security trigger
    if [ "$i" -eq 1 ]; then
        docker exec "$CNAME" /bin/sh -c "for j in \$(seq 1 $EVENTS_PER_STREAM); do /bin/true; done; echo '#!/bin/sh' > /tmp/exploit_sim.sh && chmod +x /tmp/exploit_sim.sh && /tmp/exploit_sim.sh && rm -f /tmp/exploit_sim.sh" &
    else
        docker exec "$CNAME" /bin/sh -c "for j in \$(seq 1 $EVENTS_PER_STREAM); do /bin/true; done" &
    fi
    PIDS+=("$!")
done

echo "[3/6] Awaiting completion of all concurrent workload streams..."
for pid in "${PIDS[@]}"; do
    wait "$pid"
done

T_END=$(date +%s.%N)
ELAPSED=$(echo "$T_END - $T_START" | bc)
echo "[+] All worker streams finished in ${ELAPSED}s"

# If backpressure pause was applied, wait for reader to resume and drain
if [ "$PAUSE_SEC" -gt 0 ]; then
    EXTRA_WAIT=$(( PAUSE_SEC + 3 ))
    echo "[+] Waiting ${EXTRA_WAIT}s for backpressure pause to release and pipeline to drain..."
    sleep "$EXTRA_WAIT"
else
    sleep 3
fi

kill "$SAMPLER_PID" 2>/dev/null || true

echo "[4/6] Shutting down ContainerGuard daemon..."
kill -TERM "$CG_PID"
wait "$CG_PID" 2>/dev/null || true
trap - EXIT INT TERM

# Clean up temporary worker containers
for c in "${TEMP_CONTAINERS[@]}"; do
    docker rm -f "$c" >/dev/null 2>&1 || true
done

echo "[5/6] Extracting final telemetry integrity accounting..."
sed -n '/=== FINAL TELEMETRY INTEGRITY ACCOUNTING REPORT ===/,$p' "$DAEMON_LOG" | tail -n +2 > "$REPORT_JSON"

echo "[6/6] Computing Saturation and Telemetry Boundary Analysis..."

python3 - <<PYEOF
import json, os

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
peak_queue = data.get("peak_pending_queue_depth", 0)
current_queue = data.get("current_pending_queue_depth", 0)
queue_overflows = data.get("userspace_queue_overflows", 0)

elapsed = float("$ELAPSED")
target_total = int("$TOTAL_TARGET")

# Calculate resource usage
max_cpu = 0.0
max_rss_kb = 0
if os.path.exists("$RESOURCE_LOG"):
    with open("$RESOURCE_LOG") as rf:
        for line in rf:
            parts = line.strip().split()
            if len(parts) >= 2:
                try:
                    c = float(parts[0])
                    r = int(parts[1])
                    if c > max_cpu: max_cpu = c
                    if r > max_rss_kb: max_rss_kb = r
                except:
                    pass

target_tput = target_total / elapsed if elapsed > 0 else 0.0
observed_tput = hooks / elapsed if elapsed > 0 else 0.0
delivery_rate = (decoded / submits * 100.0) if submits > 0 else 0.0
kernel_drop_rate = (drops / hooks * 100.0) if hooks > 0 else 0.0

print("=================================================================")
print(" SATURATION BENCHMARK EMPIRICAL REPORT: $LABEL")
print("=================================================================")
print(f" Ring Buffer Configuration:         ${RINGBUF_KB} KiB")
print(f" Backpressure Reader Pause:         ${PAUSE_SEC} seconds")
print(f" Concurrency Streams:               $NUM_STREAMS")
print(f" Target Workload Total:             {target_total}")
print(f" Elapsed Workload Time:             {elapsed:.2f} seconds")
print(f" Target Workload Throughput:        {target_tput:.1f} events/sec")
print(f" Observed Hook Throughput:          {observed_tput:.1f} hooks/sec")
print("-----------------------------------------------------------------")
print(f" Kernel Hook Invocations:           {hooks}")
print(f" Ring Buffer Submissions:           {submits}")
print(f" Ring Buffer Reservation Drops:     {drops}")
print(f" Kernel Drop Rate:                  {kernel_drop_rate:.2f}%")
print(f" Userspace Records Received:        {received}")
print(f" Userspace Records Decoded:         {decoded}")
print(f" Telemetry Delivery Rate:           {delivery_rate:.2f}%")
print(f" Sequence Gaps Detected:            {seq_gaps}")
print(f" Reordered Events Handled:          {reordered}")
print(f" Peak Pending Queue Depth:          {peak_queue}")
print(f" Final Pending Queue Depth:         {current_queue}")
print(f" Userspace Queue Overflows:         {queue_overflows}")
print(f" Container Attribution Resolved:    {resolved}")
print(f" Non-Container / Unresolved:        {unresolved}")
print(f" Peak Collector CPU:                {max_cpu:.1f}%")
print(f" Peak Collector RSS:                {max_rss_kb / 1024.0:.1f} MiB")
print("=================================================================")
if drops > 0:
    print(f"[*] SATURATION DETECTED: Kernel Ring Buffer dropped {drops} events ({kernel_drop_rate:.2f}% loss)")
elif queue_overflows > 0:
    print(f"[*] SATURATION DETECTED: Userspace queue overflowed ({queue_overflows} drops)")
elif seq_gaps > 0:
    print(f"[*] SATURATION DETECTED: Sequence gaps detected ({seq_gaps} gaps)")
else:
    print("[+] LOSSLESS DELIVERY: All kernel events accommodated without saturation")
print("=================================================================")
PYEOF
