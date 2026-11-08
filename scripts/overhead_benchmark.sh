#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EVIDENCE_DIR="${ROOT_DIR}/docs/evidence/phase_i"

mkdir -p "${EVIDENCE_DIR}"

REPORT_JSON="${EVIDENCE_DIR}/overhead_benchmark_report.json"
DAEMON_LOG="${EVIDENCE_DIR}/overhead_daemon.log"
SAMPLES_LOG="${EVIDENCE_DIR}/overhead_resource_samples.csv"

WORKLOAD_STREAMS=4
EVENTS_PER_STREAM=500
TOTAL_WORKLOAD_EVENTS=$((WORKLOAD_STREAMS * EVENTS_PER_STREAM))

echo "================================================================="
echo " ContainerGuard Phase I: Monitoring Overhead Evaluation"
echo " Target Workload: ${TOTAL_WORKLOAD_EVENTS} executions (${WORKLOAD_STREAMS} streams x ${EVENTS_PER_STREAM})"
echo "================================================================="

# Helper function to run the concurrent workload
run_workload() {
    local stream_count=$1
    local ev_per_stream=$2
    local pids=()

    for s in $(seq 1 "${stream_count}"); do
        (
            for i in $(seq 1 "${ev_per_stream}"); do
                /bin/true
            done
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "${pid}"
    done
}

# -------------------------------------------------------------
# Part 1: Baseline (Unmonitored) Benchmark
# -------------------------------------------------------------
echo "[1/4] Running Baseline (Unmonitored) Benchmark..."
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null

START_BASELINE=$(date +%s.%N)
run_workload "${WORKLOAD_STREAMS}" "${EVENTS_PER_STREAM}"
END_BASELINE=$(date +%s.%N)

DURATION_BASELINE=$(echo "${END_BASELINE} - ${START_BASELINE}" | bc -l)
THROUGHPUT_BASELINE=$(echo "${TOTAL_WORKLOAD_EVENTS} / ${DURATION_BASELINE}" | bc -l)
echo "[+] Baseline finished in ${DURATION_BASELINE}s (${THROUGHPUT_BASELINE} events/sec)"

sleep 1.0

# -------------------------------------------------------------
# Part 2: Monitored with ContainerGuard
# -------------------------------------------------------------
echo "[2/4] Starting ContainerGuard daemon for Monitored Benchmark..."
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null

sudo "${ROOT_DIR}/bin/containerguard" \
    -bpf "${ROOT_DIR}/bpf/execve_events.o" \
    -metrics-interval 1s > "${DAEMON_LOG}" 2>&1 &
DAEMON_PID=$!
echo "[+] ContainerGuard active with PID ${DAEMON_PID}"
sleep 1.0

# Start background resource sampler
echo "timestamp,cpu_pct,rss_kb" > "${SAMPLES_LOG}"
SAMPLER_RUNNING=1
(
    while [[ "${SAMPLER_RUNNING}" -eq 1 ]]; do
        if ps -p "${DAEMON_PID}" > /dev/null 2>&1; then
            STATS=$(ps -p "${DAEMON_PID}" -o %cpu,rss --no-headers 2>/dev/null || echo "0.0 0")
            CPU=$(echo "${STATS}" | awk '{print $1}')
            RSS=$(echo "${STATS}" | awk '{print $2}')
            TS=$(date +%s.%N)
            echo "${TS},${CPU},${RSS}" >> "${SAMPLES_LOG}"
        fi
        sleep 0.1
    done
) &
SAMPLER_PID=$!

echo "[3/4] Running Monitored Benchmark under active eBPF collection..."
START_MONITORED=$(date +%s.%N)
run_workload "${WORKLOAD_STREAMS}" "${EVENTS_PER_STREAM}"
END_MONITORED=$(date +%s.%N)

DURATION_MONITORED=$(echo "${END_MONITORED} - ${START_MONITORED}" | bc -l)
THROUGHPUT_MONITORED=$(echo "${TOTAL_WORKLOAD_EVENTS} / ${DURATION_MONITORED}" | bc -l)
echo "[+] Monitored workload finished in ${DURATION_MONITORED}s (${THROUGHPUT_MONITORED} events/sec)"

# Stop resource sampler
kill "${SAMPLER_PID}" 2>/dev/null || true
wait "${SAMPLER_PID}" 2>/dev/null || true

# Shut down ContainerGuard daemon
echo "[4/4] Shutting down ContainerGuard daemon..."
sudo kill -TERM "${DAEMON_PID}" || true
wait "${DAEMON_PID}" 2>/dev/null || true
echo "[+] ContainerGuard stopped gracefully."

# -------------------------------------------------------------
# Part 3: Python Statistical Analysis
# -------------------------------------------------------------
python3 - << PYEOF
import csv
import json
import os
import re

samples_csv = "${SAMPLES_LOG}"
daemon_log = "${DAEMON_LOG}"
report_path = "${REPORT_JSON}"

duration_base = float("${DURATION_BASELINE}")
duration_mon = float("${DURATION_MONITORED}")
tp_base = float("${THROUGHPUT_BASELINE}")
tp_mon = float("${THROUGHPUT_MONITORED}")
events_count = int("${TOTAL_WORKLOAD_EVENTS}")

# Process resource samples
cpu_samples = []
rss_samples = []
if os.path.exists(samples_csv):
    with open(samples_csv, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                cpu_samples.append(float(row["cpu_pct"]))
                rss_samples.append(float(row["rss_kb"]) / 1024.0) # convert KB to MiB
            except (ValueError, KeyError):
                pass

avg_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0.0
peak_cpu = max(cpu_samples) if cpu_samples else 0.0
avg_rss = sum(rss_samples) / len(rss_samples) if rss_samples else 0.0
peak_rss = max(rss_samples) if rss_samples else 0.0

overhead_time_pct = ((duration_mon - duration_base) / duration_base) * 100.0
throughput_delta_pct = ((tp_mon - tp_base) / tp_base) * 100.0

# Extract final telemetry metrics JSON from daemon log
accounting = {}
if os.path.exists(daemon_log):
    with open(daemon_log, "r") as f:
        content = f.read()
        match = re.search(r"=== FINAL TELEMETRY INTEGRITY ACCOUNTING REPORT ===\s*(\{.*?\})", content, re.DOTALL)
        if match:
            accounting = json.loads(match.group(1))

report = {
    "workload_parameters": {
        "target_workload_events": events_count,
        "concurrent_streams": int("${WORKLOAD_STREAMS}"),
        "events_per_stream": int("${EVENTS_PER_STREAM}")
    },
    "baseline_unmonitored": {
        "execution_time_seconds": round(duration_base, 4),
        "throughput_events_per_sec": round(tp_base, 2)
    },
    "containerguard_monitored": {
        "execution_time_seconds": round(duration_mon, 4),
        "throughput_events_per_sec": round(tp_mon, 2),
        "daemon_cpu_avg_pct": round(avg_cpu, 2),
        "daemon_cpu_peak_pct": round(peak_cpu, 2),
        "daemon_rss_avg_mib": round(avg_rss, 2),
        "daemon_rss_peak_mib": round(peak_rss, 2)
    },
    "overhead_analysis": {
        "execution_time_overhead_pct": round(overhead_time_pct, 2),
        "throughput_impact_pct": round(throughput_delta_pct, 2),
        "workload_wallclock_delta_per_event_us": round(((duration_mon - duration_base) / events_count) * 1e6, 2),
        "methodology_note": "Amortized workload wall-clock time difference per event across concurrent process lifecycles. Does not isolate pure kernel syscall entry-to-exit latency."
    },
    "telemetry_conservation": {
        "kernel_hook_calls": accounting.get("kernel_hook_invocations", 0),
        "kernel_submissions": accounting.get("kernel_ringbuf_submitted", 0),
        "kernel_reserve_drops": accounting.get("kernel_ringbuf_reserve_drops", 0),
        "userspace_decoded": accounting.get("userspace_records_decoded", 0),
        "delivery_rate_pct": round((accounting.get("userspace_records_decoded", 0) / accounting.get("kernel_ringbuf_submitted", 1)) * 100.0, 4) if accounting.get("kernel_ringbuf_submitted", 0) > 0 else 100.0
    }
}

hook_calls = accounting.get("kernel_hook_invocations", 0)
submitted = accounting.get("kernel_ringbuf_submitted", 0)
drops = accounting.get("kernel_ringbuf_reserve_drops", 0)
decoded = accounting.get("userspace_records_decoded", 0)

if hook_calls != (submitted + drops):
    print(f"\n[!] INVARIANT VIOLATION: Hooks ({hook_calls}) != Submissions ({submitted}) + Drops ({drops})")
    import sys; sys.exit(1)

if decoded > submitted:
    print(f"\n[!] BENCHMARK INVALIDATED: Decoded ({decoded}) > Submissions ({submitted})!")
    import sys; sys.exit(1)

with open(report_path, "w") as f:
    json.dump(report, f, indent=2)

print("\n" + "="*65)
print(" MONITORING OVERHEAD EVALUATION SUMMARY")
print("="*65)
print(f" Target Workload:               {events_count} executions ({report['workload_parameters']['concurrent_streams']} streams x {report['workload_parameters']['events_per_stream']})")
print(f" Baseline (Unmonitored) Time:   {duration_base:.4f}s ({tp_base:.2f} events/sec)")
print(f" Monitored (ContainerGuard):    {duration_mon:.4f}s ({tp_mon:.2f} events/sec)")
print("-" * 65)
print(f" Execution Time Overhead:       {overhead_time_pct:+.2f}%")
print(f" Throughput Impact:             {throughput_delta_pct:+.2f}%")
print(f" Workload Wall-Clock Delta / Ev:{report['overhead_analysis']['workload_wallclock_delta_per_event_us']:.2f} microseconds (amortized process lifecycle)")
print("-" * 65)
print(f" Daemon CPU Utilization (Avg):  {avg_cpu:.2f}% (Peak: {peak_cpu:.2f}%)")
print(f" Daemon RSS Memory (Avg):       {avg_rss:.2f} MiB (Peak: {peak_rss:.2f} MiB)")
print("-" * 65)
print(f" Kernel Hook Calls Observed:    {report['telemetry_conservation']['kernel_hook_calls']}")
print(f" Ring Buffer Reserve Drops:     {report['telemetry_conservation']['kernel_reserve_drops']}")
print(f" Telemetry Delivery Rate:       {report['telemetry_conservation']['delivery_rate_pct']:.2f}%")
print("="*65)
PYEOF

echo "[+] Phase I overhead benchmark finished. Report saved to ${REPORT_JSON}."
