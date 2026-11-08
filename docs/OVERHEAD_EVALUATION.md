# Monitoring Overhead and System Resource Evaluation Report

**Release Milestone:** ContainerGuard 50% Verified Milestone  
**Test Harness:** `scripts/overhead_benchmark.sh`  
**Evaluated Workload:** 2,000 process executions (`/bin/true`) across 4 worker streams (500 executions each)  
**Evidence Artifacts:**
- Trial 1 (Commit `7c56b1e`): [`evidence/phase_i/overhead_benchmark_report.json`](evidence/phase_i/overhead_benchmark_report.json) (archived at `7c56b1e`)
- Trial 2 (Commit `b8f70f5`): [`evidence/phase_i/overhead_benchmark_report.json`](evidence/phase_i/overhead_benchmark_report.json) (current milestone rerun)
- Resource Samples: [`evidence/phase_i/overhead_resource_samples.csv`](evidence/phase_i/overhead_resource_samples.csv)

---

## 1. Experimental Methodology & Benchmark Protocol

To measure runtime overhead introduced by ContainerGuard's multi-tracepoint eBPF telemetry engine, an intensive execution benchmark was conducted under strictly identical workload parameters:
1. **Workload:** 2,000 rapid process executions (`/bin/true`) dispatched concurrently across 4 worker streams (500 executions per stream).
2. **Environment Normalization:** Page cache, dentries, and inodes flushed prior to testing (`echo 3 > /proc/sys/vm/drop_caches`).
3. **Execution Modes Compared:**
   - **Baseline (Unmonitored):** Workload executed with no eBPF programs loaded and no monitoring daemon running.
   - **Monitored (ContainerGuard Active):** Daemon active with 5 kernel tracepoints (`sys_enter_execve`, `sys_enter_execveat`, `sched_process_exec`, `sys_exit_execve`, `sys_exit_execveat`), live ring buffer ingestion, container attribution, lineage tracking, and detection rule evaluation.
4. **Sampling:** Daemon CPU (%) and resident memory RSS (KiB) sampled at 100ms intervals throughout workload execution.

---

## 2. Empirical Performance Measurements Across Software Revisions

The overhead benchmark was evaluated across two software revisions:
- **Trial 1:** Initial Phase I implementation (Commit `7c56b1e`).
- **Trial 2:** Frozen 50% Milestone release build (Commit `b8f70f5`).

| Performance Dimension | Trial 1 (Commit `7c56b1e`) | Trial 2 (Commit `b8f70f5`) | Descriptive Mean ($\mu$) | Variation / Spread |
| :--- | :---: | :---: | :---: | :---: |
| **Unmonitored Baseline Duration** | 0.4492 s (4,451.91 ev/s) | 0.4267 s (4,687.34 ev/s) | 0.4380 s | Baseline variance: $\pm 0.0113\text{ s}$ |
| **Monitored Workload Duration** | 0.4648 s (4,303.08 ev/s) | 0.4520 s (4,424.29 ev/s) | 0.4584 s | Monitored variance: $\pm 0.0064\text{ s}$ |
| **Execution Time Overhead (%)** | **+3.46%** | **+5.95%** | **4.71%** | Sample $s \approx 1.76\%$, $SEM \approx 1.25\%$ ($N=2$) |
| **Throughput Impact (%)** | -3.34% | -5.61% | -4.48% | $\pm 1.14\%$ |
| **Amortized Wall-Clock Delta / Lifecycle**| **$7.77\ \mu\text{s}$** | **$12.68\ \mu\text{s}$** | **$10.22\ \mu\text{s}$** | $\pm 2.45\ \mu\text{s}$ |
| **Daemon CPU Footprint** | $< 0.1\%$ | $0.75\%$ avg / $0.90\%$ peak | *Unpooled* | Trial 1 below resolution; no pooled mean |
| **Daemon RSS Memory Footprint** | 6.02 MiB | 6.04 MiB | 6.03 MiB | $\pm 0.01\text{ MiB}$ |
| **Telemetry Delivery (Hooks = Submits)** | 2,036 / 2,036 (100.0%) | 2,036 / 2,036 (100.0%) | 100.0% | 0 drops across both trials |

---

## 3. Methodological Definition: Amortized Wall-Clock Delta

$$\text{Amortized Wall-Clock Delta per Lifecycle} = \frac{T_{\text{monitored}} - T_{\text{baseline}}}{N_{\text{events}}}$$

- **Trial 1:** $\frac{0.46478\text{ s} - 0.44925\text{ s}}{2000} \approx 7.77 \times 10^{-6}\text{ seconds} = \mathbf{7.77\ \mu\text{s}}$
- **Trial 2:** $\frac{0.45204\text{ s} - 0.42672\text{ s}}{2000} \approx 12.68 \times 10^{-6}\text{ seconds} = \mathbf{12.68\ \mu\text{s}}$

> [!IMPORTANT]
> **Measurement Qualification:** The values of $7.77\ \mu\text{s}$ and $12.68\ \mu\text{s}$ represent the **amortized workload wall-clock time difference per process lifecycle** (including fork, execve, address space instantiation, and termination) under multi-core concurrency. **They do not represent isolated kernel syscall entry-to-exit latency.**

---

## 4. Statistical Limitations & Sample Size Notice

> [!WARNING]
> Across two benchmark trials on separate software commits (`7c56b1e` and `b8f70f5`), the measured execution overhead was $3.46\%$ and $5.95\%$, yielding a descriptive mean of $4.71\%$.
> - Because the measurements used different software revisions and only two observations ($N = 2$), **the descriptive mean of 4.71% should not be interpreted as a reliable estimate of production performance overhead.**
> - The observed variation is influenced by WSL2 host virtualization scheduling jitter in the unmonitored baseline ($0.4267\text{ s}$ vs $0.4492\text{ s}$, a $5.27\%$ baseline variance).
> - Any future performance study requires repeated baseline and monitored runs using the identical frozen release binary and matched workloads in an isolated physical hardware environment.
