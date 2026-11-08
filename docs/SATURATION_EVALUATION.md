# ContainerGuard: Controlled Ring Buffer Saturation and Telemetry Boundary Evaluation (Phase H.2)

## 1. Experimental Methodology and Rationale

In Phase H, ContainerGuard demonstrated 100% telemetry delivery across workloads up to 25,000 events without any ring buffer reservation drops. While this established high throughput scalability (up to 1,923 hooks/sec), it did not identify the kernel ring buffer saturation threshold.

The objective of Phase H.2 is to scientifically define, induce, and empirically measure the **telemetry loss boundary**:
1. What workload and buffer configurations cause kernel-side drops (`bpf_ringbuf_reserve` failures)?
2. How does ContainerGuard account for dropped telemetry when the userspace reader experiences backpressure?
3. How are kernel-side reservation drops distinguished from transport-layer sequence gaps?
4. How quickly does the system recover once transient backpressure ceases?

---

## 2. Theoretical Memory Model & Capacity Bounds

### 2.1 Struct Layout and Frame Footprint
Inspection of the compiled BPF object (`bpf/execve_events.o`) via `pahole` confirms the exact memory layout:
```c
struct exec_event {
    __u64 timestamp_ns;         /* 0   8 bytes */
    __u64 cgroup_id;            /* 8   8 bytes */
    __u64 seq_num;              /* 16  8 bytes */
    __u64 start_time_ns;        /* 24  8 bytes */
    __u64 parent_start_time_ns; /* 32  8 bytes */
    __u32 tid;                  /* 40  4 bytes */
    __u32 tgid;                 /* 44  4 bytes */
    __u32 parent_tgid;          /* 48  4 bytes */
    __u32 uid;                  /* 52  4 bytes */
    __u32 gid;                  /* 56  4 bytes */
    __u32 flags;                /* 60  4 bytes */
    char  comm[16];             /* 64 16 bytes */
    char  filename[256];        /* 80 256 bytes */
};
/* Total size: 336 bytes, 6 cachelines */
```
* **Kernel BPF Ring Buffer Header:** In the Linux kernel (`kernel/bpf/ringbuf.c`), `bpf_ringbuf_reserve()` prepends an 8-byte record header:
  `struct bpf_ringbuf_hdr { __u32 len; __u32 pg_off; };`
* **Length Alignment:** Record length is rounded to 8-byte boundaries via `roundup(len + BPF_RINGBUF_HDR_SZ, 8)`.
  $$\text{Record Wire Footprint} = \text{roundup}(336 + 8, 8) = \mathbf{344\text{ bytes}}$$

### 2.2 Mathematical Capacity Bounds
$$\text{Max Buffered Events} = \left\lfloor \frac{\text{Ring Buffer Size (bytes)}}{344\text{ bytes/event}} \right\rfloor$$

| Ring Buffer Sizing | Size in Bytes | Theoretical Unconsumed Limit | Observed Saturated Count (During Reader Pause) |
|---|---|---|---|
| **64 KiB** | 65,536 bytes | $\lfloor 65,536 / 344 \rfloor = \mathbf{190\text{ events}}$ | **190 events** (100% match) |
| **256 KiB** | 262,144 bytes | $\lfloor 262,144 / 344 \rfloor = \mathbf{762\text{ events}}$ | **762 events** (100% match) |
| **1,024 KiB (1 MiB)** | 1,048,576 bytes | $\lfloor 1,048,576 / 344 \rfloor = \mathbf{3,048\text{ events}}$ | $> 2,087$ events (Lossless) |
| **16,384 KiB (16 MiB)** | 16,777,216 bytes | $\lfloor 16,777,216 / 344 \rfloor = \mathbf{48,770\text{ events}}$ | $> 25,032$ events (Lossless) |

---

## 3. Phase H.2 Evidence Audit: Root Cause Analysis

An audit of the initial Phase H.2 runs identified four accounting anomalies, all of which have been diagnosed, corrected, and verified:

### 3.1 Audit Item 1: Why did delivery rate report 100.33% (2,100 submitted vs 2,107 decoded)?
* **Root Cause:** A race condition in the daemon shutdown sequence between map closing and final metrics synchronization.
  In `internal/collector/collector.go`, an asynchronous `<-ctx.Done()` goroutine was closing `c.collection` (unloading map file descriptors) immediately upon SIGTERM. Concurrently, the final `PollKernelMetrics()` ticker call failed to read `telemetry_counters` because the map was already closed, leaving `KernelRingBufferSubmit` frozen at its previous 1-second ticker value of 2,100.
  Meanwhile, the ring buffer reader was still actively draining the remaining 7 records that occurred during shutdown teardown, resulting in `UserspaceRecordsDecoded = 2,107`.
* **Fix Applied:**
  1. Refactored collector shutdown so `<-ctx.Done()` calls `bpfCollector.StopReader()` (closing only the reader FD to unblock the drain loop) while keeping BPF maps open.
  2. In `cmd/containerguard/main.go`, `bpfCollector.PollKernelMetrics()` is called **synchronously after** all in-flight events have drained, ensuring the final kernel counters reflect all submitted events.
  3. Delivery rate formula is clamped to `min(100.0, ...)`.

### 3.2 Audit Item 2: Why did final reports show 229 and 805 accepted events instead of 190 and 762?
* **Investigation:** Inspection of the 1-second periodic metric snapshots in `daemon.log` during the reader freeze revealed:
  - In `sat_bp_64kb`: At $t = 5\text{s}$ (during the pause, before reader unpaused), `kernel_ringbuf_submitted` was **exactly 190**, and `kernel_ringbuf_reserve_drops` was **1,846**.
  - In `sat_bp_256kb`: At $t = 5\text{s}$ (during the pause), `kernel_ringbuf_submitted` was **exactly 762**, and `kernel_ringbuf_reserve_drops` was **1,282**.
* **Finding:** During the reader freeze, the kernel ring buffer held **EXACTLY 190 events (for 64 KiB)** and **EXACTLY 762 events (for 256 KiB)**, matching the theoretical mathematical limits to the single integer.
* The trailing accepted records (39 in the 64 KiB run, 43 in the 256 KiB run) occurred *after* the 4-second backpressure pause released, when the reader resumed draining and accepted trailing container teardown commands into the now-empty ring buffer.

### 3.3 Audit Item 3: Why did `current_pending_queue_depth` report 19 on exit in the 16 MiB run?
* **Investigation:** Analysis of the last 10 records in `daemon.log` revealed that the background resource sampler (`ps -p $CG_PID` and `sleep 0.2`) executed repeatedly right up until daemon SIGTERM.
* Because host processes are buffered with a 2-second TTL (`-pending-ttl 2s`), the 19 `ps` and `sleep` executions that arrived in the final 0.5s before SIGTERM were still waiting for their TTL to elapse when the process terminated.
* **Fix Applied:** Added `buffer.Flush()` to the shutdown sequence in `cmd/containerguard/main.go`, which force-expires all lingering pending events to `UNRESOLVED` and drains `CurrentPendingQueueDepth` to **0**.

### 3.4 Audit Item 4: Parser failure in `sat_256kb_8stream`
* **Root Cause:** In `scripts/saturation_test.sh`, trailing daemon log text was appended after the closing JSON bracket `}` in `report.json`.
* **Fix Applied:** Replaced shell `sed` extraction with a strict Python JSON delimiter block extractor.

---

## 4. Empirical Test Suite 1: Capacity Sensitivity Under Concurrency (Active Drain)

* **Workload:** 8 concurrent container streams $\times$ 250 executions = 2,000 target events.
* **Duration:** 0.34s – 0.90s (~2,300 to 6,084 hooks/sec).
* **Consumer State:** Actively draining without backpressure.

```
===================================================================================================================
BENCHMARK RUN                       sat_16mb_8stream    sat_1mb_8stream     sat_256kb_8stream   sat_64kb_8stream
===================================================================================================================
Ring Buffer Sizing                  16,384 KiB (16 MiB) 1,024 KiB (1 MiB)   256 KiB             64 KiB
Concurrency Streams                 8 streams           8 streams           8 streams           8 streams
Target Workload Events              2,000               2,000               2,000               2,000
Workload Elapsed Time               0.87 seconds        0.85 seconds        0.34 seconds        0.86 seconds
Target Workload Throughput          2,285.8 ev/s        2,343.6 ev/s        5,844.5 ev/s        2,318.2 ev/s
Observed Hook Throughput            2,385.3 hooks/s     2,445.6 hooks/s     6,084.1 hooks/s     2,419.0 hooks/s
Kernel Hook Invocations             2,087               2,087               2,082               2,087
Ring Buffer Submissions             2,087               2,087               2,082               2,087
Ring Buffer Reservation Drops       0 (0.00%)           0 (0.00%)           0 (0.00%)           0 (0.00%)
Userspace Records Decoded           2,087               2,087               2,082               2,087
Telemetry Delivery Rate             100.00%             100.00%             100.00%             100.00%
Sequence Gaps Detected              0                   0                   0                   0
Container Attributed Events         2,028               2,028               2,027               2,028
Container Attribution Recall        100% (2028/2028)    100% (2028/2028)    100% (2027/2027)    100% (2028/2028)
Non-Container (UNRESOLVED)          59                  59                  55                  59
Final Pending Queue Depth           0                   0                   0                   0
Peak Collector CPU                  21.9%               17.6%               21.0%               18.3%
Peak Collector RSS Memory           56.5 MiB            25.0 MiB            25.6 MiB            25.4 MiB
Status                              LOSSLESS            LOSSLESS            LOSSLESS            LOSSLESS
===================================================================================================================
```

---

## 5. Empirical Test Suite 2: Induced Userspace Backpressure & Failure Boundary

* **Workload:** 4 concurrent container streams $\times$ 500 executions = 2,000 target events.
* **Consumer State:** Userspace reader paused for **4.0 seconds** (`-backpressure-pause-sec 4`). Workload finishes completely during the pause ($0.46\text{s} - 0.53\text{s}$).

### Side-by-Side Comparison: Initial vs. Audited Reconciled Runs

```
===================================================================================================================
METRIC / CONFIGURATION              16 MiB (Initial)    16 MiB (Audited)    256 KiB (Audited)   64 KiB (Audited)
===================================================================================================================
Ring Buffer Sizing                  16,384 KiB          16,384 KiB          256 KiB             64 KiB
Backpressure Reader Pause           4.0 seconds         4.0 seconds         4.0 seconds         4.0 seconds
Target Workload Events              2,000               2,000               2,000               2,000
Workload Elapsed Time               1.23s               0.53s               0.51s               0.46s
Target Workload Throughput          1,624.3 ev/s        3,801.7 ev/s        3,892.0 ev/s        4,301.8 ev/s
Observed Hook Throughput            1,705.5 hooks/s     4,001.3 hooks/s     4,090.5 hooks/s     4,525.5 hooks/s
Kernel Hook Invocations             2,100               2,105               2,102               2,104
Kernel Ring Buffer Submissions      2,100               2,105 (100.0%)      801 (38.11%)        231 (10.98%)
Kernel Ring Buffer Reserve Drops    0 (0.00%)           0 (0.00%)           1,301 (61.89%)      1,873 (89.02%)
Accepted Events During Pause        2,015 (All)         2,015 (All)         762 (Exact limit)   190 (Exact limit)
Userspace Records Decoded           2,107* (stale poll) 2,105 (Exact match) 801 (Exact match)   231 (Exact match)
Telemetry Delivery Rate             100.33%* (Anomaly)  100.00%             100.00%             100.00%
Sequence Gaps Detected              0                   0                   0                   0
Container Attributed Events         2,015               2,015               748                 179
Non-Container (UNRESOLVED)          73                  90                  53                  52
Final Pending Queue Depth           19* (Sampler lag)   0 (Clean drain)     0 (Clean drain)     0 (Clean drain)
Peak Collector RSS Memory           56.0 MiB            53.6 MiB            24.0 MiB            21.9 MiB
Failure Boundary Identified?        NO (Capacity >> 2k) NO (Capacity >> 2k) YES (Saturated)     YES (Saturated)
Empirical Drop Rate                 0.00%               0.00%               61.89%              89.02%
===================================================================================================================
```
*\*Notes on Initial Run:* Documented in Section 3 as resolved shutdown synchronization anomalies. The audited rerun confirms 100.00% exact mathematical balance.

---

## 6. Scientific Conclusions and Mathematical Conservation

1. **Exact Mathematical Conservation:**
   $$\text{Kernel Hooks} = \text{Ring Buffer Submissions} + \text{Ring Buffer Reservation Drops}$$
   - In 16 MiB: $2,105 = 2,105 + 0$ (100.00% accounted)
   - In 256 KiB: $2,102 = 801 + 1,301$ (100.00% accounted)
   - In 64 KiB: $2,104 = 231 + 1,873$ (100.00% accounted)
   Every single dropped event was captured and counted by the atomic kernel array map `telemetry_counters[CG_METRIC_RB_RESERVE_DROPS]`. Zero events were silently lost.
2. **Failure Boundary Precision:** During the reader pause, the kernel ring buffer accepted **exactly 190 events for 64 KiB** ($\lfloor 65,536 / 344 \rfloor = 190$) and **exactly 762 events for 256 KiB** ($\lfloor 262,144 / 344 \rfloor = 762$), confirming the theoretical memory model.
3. **Decoupled Sequence Semantics:** Kernel reservation drops occur before sequence ticket allocation. Therefore, dropped records never consume sequence numbers, preserving sequence contiguity for successfully committed records (`sequence_gaps_detected = 0`).
4. **Graceful Recovery:** In all saturation tests, when the backpressure pause released, the userspace reader drained the buffered records cleanly, resolved container identities, and shut down without memory leaks, panics, or hangs.

---

## 7. Artifact Archival

* **Audited Verified Evidence:**
  - `docs/evidence/phase_h2/suite1_capacity_8stream/`
  - `docs/evidence/phase_h2/suite2_backpressure/`
* **Original Unreconciled Evidence (Preserved for Audit Trail):**
  - `docs/evidence/phase_h2/original_unreconciled/`
* **Compiled Binary SHA-256 Hashes:**
  - `bin/containerguard`: `fcb2d144ea37e12d5d9838299f1ac3e61b166be21ace9d88878e7d40b79c0553`
  - `bpf/execve_events.o`: `a03f97cbff8a7539757b86810bb73769c5d9a15639c10129915b99ce23dafaec`
