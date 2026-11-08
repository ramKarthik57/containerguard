# ContainerGuard: Controlled Ring Buffer Saturation and Telemetry Boundary Evaluation (Phase H.2)

## 1. Experimental Methodology and Rationale

In Phase H, ContainerGuard demonstrated 100% telemetry delivery across workloads up to 25,000 events without any ring buffer reservation drops. While this established high throughput scalability (up to 1,923 hooks/sec), it did not identify the kernel ring buffer saturation threshold.

The objective of Phase H.2 is to scientifically define, induce, and empirically measure the **telemetry loss boundary**:
1. What workload and buffer configurations cause kernel-side drops (`bpf_ringbuf_reserve` failures)?
2. How does ContainerGuard account for dropped telemetry when the userspace reader experiences backpressure?
3. How are kernel-side reservation drops distinguished from transport-layer sequence gaps?
4. How quickly does the system recover once transient backpressure ceases?

---

## 2. Event Schemas & Mathematical Capacity Bounds

During project development, the eBPF event structure evolved across two revisions. To ensure scientific reproducibility, both schemas and their corresponding theoretical capacities are documented below.

### 2.1 Schema Comparison: Phase H.2 Benchmark vs. Frozen 50% Milestone Release

```c
/* Schema A: Phase H.2 Saturation Benchmark (Commit 96f36ce) */
struct exec_event_phase_h2 {
    __u64 timestamp_ns;         /* Offset   0: 8 bytes */
    __u64 cgroup_id;            /* Offset   8: 8 bytes */
    __u64 seq_num;              /* Offset  16: 8 bytes */
    __u64 start_time_ns;        /* Offset  24: 8 bytes */
    __u64 parent_start_time_ns; /* Offset  32: 8 bytes */
    __u32 tid;                  /* Offset  40: 4 bytes */
    __u32 tgid;                 /* Offset  44: 4 bytes */
    __u32 parent_tgid;          /* Offset  48: 4 bytes */
    __u32 uid;                  /* Offset  52: 4 bytes */
    __u32 gid;                  /* Offset  56: 4 bytes */
    __u32 flags;                /* Offset  60: 4 bytes */
    char  comm[16];             /* Offset  64: 16 bytes */
    char  filename[256];        /* Offset  80: 256 bytes */
}; /* Total Payload: 336 bytes */

/* Schema B: Frozen 50% Milestone Release (Commit b8f70f5) */
struct exec_event_frozen_release {
    __u64 timestamp_ns;         /* Offset   0: 8 bytes */
    __u64 cgroup_id;            /* Offset   8: 8 bytes */
    __u64 parent_cgroup_id;     /* Offset  16: 8 bytes (+8B parent cgroup) */
    __u64 seq_num;              /* Offset  24: 8 bytes */
    __u64 start_time_ns;        /* Offset  32: 8 bytes */
    __u64 parent_start_time_ns; /* Offset  40: 8 bytes */
    __u32 tid;                  /* Offset  48: 4 bytes */
    __u32 tgid;                 /* Offset  52: 4 bytes */
    __u32 parent_tgid;          /* Offset  56: 4 bytes */
    __u32 uid;                  /* Offset  60: 4 bytes */
    __u32 gid;                  /* Offset  64: 4 bytes */
    __u32 flags;                /* Offset  68: 4 bytes */
    __s32 dfd;                  /* Offset  72: 4 bytes (+4B dirfd) */
    __u32 at_flags;             /* Offset  76: 4 bytes (+4B at_flags) */
    __s32 exit_code;            /* Offset  80: 4 bytes (+4B exit_code) */
    __u32 euid;                 /* Offset  84: 4 bytes (+4B euid) */
    char  comm[16];             /* Offset  88: 16 bytes */
    char  filename[256];        /* Offset 104: 256 bytes */
}; /* Total Payload: 360 bytes */
```

### 2.2 Wire Footprint & Kernel Ring Buffer Header
In the Linux kernel (`kernel/bpf/ringbuf.c`), `bpf_ringbuf_reserve()` prepends an 8-byte record header (`struct bpf_ringbuf_hdr { __u32 len; __u32 pg_off; };`) and rounds up allocations to 8-byte alignment:
- **Phase H.2 Wire Footprint:** $\text{roundup}(336 + 8, 8) = \mathbf{344\text{ bytes}}$ per record.
- **Frozen Release Wire Footprint:** $\text{roundup}(360 + 8, 8) = \mathbf{368\text{ bytes}}$ per record.

### 2.3 Theoretical Capacity vs. Empirical Phase H.2 Observations

$$\text{Theoretical Capacity} = \left\lfloor \frac{\text{Ring Buffer Size (bytes)}}{\text{Wire Footprint (bytes)}} \right\rfloor$$

| Ring Buffer Configuration | Buffer Size in Bytes | Phase H.2 Capacity (344B Wire) | Phase H.2 Empirical Observation (During 4s Reader Freeze) | Frozen Release Capacity (368B Wire) |
| :--- | :---: | :---: | :---: | :---: |
| **64 KiB** | 65,536 B | $\lfloor 65,536 / 344 \rfloor = \mathbf{190\text{ events}}$ | **190 events** (100% exact match) | $\lfloor 65,536 / 368 \rfloor = \mathbf{178\text{ events}}$ |
| **256 KiB** | 262,144 B | $\lfloor 262,144 / 344 \rfloor = \mathbf{762\text{ events}}$ | **762 events** (100% exact match) | $\lfloor 262,144 / 368 \rfloor = \mathbf{712\text{ events}}$ |
| **1,024 KiB (1 MiB)** | 1,048,576 B | $\lfloor 1,048,576 / 344 \rfloor = \mathbf{3,048\text{ events}}$ | $> 2,087$ events (Lossless) | $\lfloor 1,048,576 / 368 \rfloor = \mathbf{2,849\text{ events}}$ |
| **16,384 KiB (16 MiB)**| 16,777,216 B | $\lfloor 16,777,216 / 344 \rfloor = \mathbf{48,770\text{ events}}$ | $> 25,032$ events (Lossless) | $\lfloor 16,777,216 / 368 \rfloor = \mathbf{45,590\text{ events}}$ |

> **Methodological Note:** The empirical values of **190** and **762** accepted events during the 4-second backpressure freeze are historical empirical findings measured on the 344-byte schema at commit `96f36ce`. For the frozen 50% milestone binary (`b8f70f5`, 368-byte wire footprint), the theoretical buffer capacities shift to **178** and **712** events, respectively.

---

## 3. Phase H.2 Evidence Audit: Root Cause Analysis

An audit of the initial Phase H.2 runs identified four accounting anomalies, all of which were diagnosed, corrected, and verified:

### 3.1 Audit Item 1: Delivery Rate Discrepancy (2,100 submitted vs 2,107 decoded)
* **Root Cause:** Asynchronous shutdown race condition. The collector goroutine closed map file descriptors before the final metrics query completed, leaving submitted counters frozen while the reader drained the remaining 7 records.
* **Correction Applied:** Refactored collector shutdown so `StopReader()` unblocks the drain loop while keeping BPF maps open until `PollKernelMetrics()` executes synchronously after all events have drained.

### 3.2 Audit Item 2: Distinguishing Experimental Runs and Final Accepted Counts

To avoid ambiguity across experimental iterations, two distinct backpressure runs are preserved in the evidence archive:

1. **Pre-Reconciliation Audit Run (`evidence/phase_h2/original_unreconciled/`):**
   - Conducted during initial Phase H.2 root-cause investigation.
   - Periodic snapshots confirmed that during the 4.0-second pause (at $t = 5\text{s}$), the 64 KiB buffer held **exactly 190 events** and the 256 KiB buffer held **exactly 762 events**, matching theoretical limits.
   - When the reader resumed, trailing container teardown commands were accepted post-pause (39 in 64 KiB, 43 in 256 KiB), resulting in final accepted totals of **229 events** ($190 + 39$) and **805 events** ($762 + 43$).
2. **Final Audited Verification Suite (`evidence/phase_h2/suite2_backpressure/`):**
   - Conducted as the official audited benchmark rerun after accounting corrections were committed (`96f36ce`).
   - Again confirmed that during the 4.0-second pause window, the buffer accepted **exactly 190 events** (64 KiB) and **762 events** (256 KiB) before drops occurred.
   - Post-pause trailing execution activity accepted 41 events (64 KiB) and 39 events (256 KiB), resulting in the final submission counts reported in the Test Suite 2 table below: **231 events** ($190 + 41$) and **801 events** ($762 + 39$).

### 3.3 Audit Item 3: Residual Pending Queue Depth at Exit
* **Investigation:** Background test harness processes (`ps`, `sleep`) executed immediately prior to SIGTERM were held in the pending attribution buffer.
* **Correction Applied:** Added `buffer.Flush()` to force-expire lingering pending events to `UNRESOLVED`, draining queue depth to **0** at exit.

### 3.4 Audit Item 4: Parser Failure in `sat_256kb_8stream`
* **Correction Applied:** Replaced shell `sed` extraction with a strict Python JSON block delimiter parser in benchmark tooling.

---

## 4. Empirical Test Suite 1: Capacity Sensitivity Under Concurrency (Active Drain)

* **Workload:** 8 concurrent container streams $\times$ 250 executions = 2,000 target events.
* **Consumer State:** Actively draining without backpressure.

| Benchmark Metric | `sat_16mb_8stream` | `sat_1mb_8stream` | `sat_256kb_8stream` | `sat_64kb_8stream` |
| :--- | :---: | :---: | :---: | :---: |
| **Ring Buffer Sizing** | 16,384 KiB (16 MiB) | 1,024 KiB (1 MiB) | 256 KiB | 64 KiB |
| **Concurrency Streams** | 8 | 8 | 8 | 8 |
| **Target Workload Events** | 2,000 | 2,000 | 2,000 | 2,000 |
| **Workload Elapsed Time** | 0.87 s | 0.85 s | 0.34 s | 0.86 s |
| **Target Throughput** | 2,285.8 ev/s | 2,343.6 ev/s | 5,844.5 ev/s | 2,318.2 ev/s |
| **Observed Hook Rate** | 2,385.3 hooks/s | 2,445.6 hooks/s | 6,084.1 hooks/s | 2,419.0 hooks/s |
| **Kernel Hook Calls** | 2,087 | 2,088 | 2,082 | 2,089 |
| **Ring Buffer Submissions**| 2,087 | 2,088 | 2,082 | 2,089 |
| **Ring Buffer Reserve Drops**| **0 (0.00%)** | **0 (0.00%)** | **0 (0.00%)** | **0 (0.00%)** |
| **Userspace Decoded Records**| 2,087 | 2,088 | 2,082 | 2,089 |
| **Telemetry Delivery Rate** | **100.00%** | **100.00%** | **100.00%** | **100.00%** |
| **Conservation Equation** | $2,087 = 2,087 + 0$ | $2,088 = 2,088 + 0$ | $2,082 = 2,082 + 0$ | $2,089 = 2,089 + 0$ |

---

## 5. Empirical Test Suite 2: Induced 4-Second Reader Backpressure

* **Workload:** 4 concurrent streams $\times$ 500 executions = 2,000 target events.
* **Consumer State:** Reader paused for 4.0 seconds after startup.

| Benchmark Metric | `sat_bp_16mb` (16 MiB) | `sat_bp_256kb` (256 KiB) | `sat_bp_64kb` (64 KiB) |
| :--- | :---: | :---: | :---: |
| **Kernel Hook Invocations** | 2,105 | 2,102 | 2,104 |
| **Ring Buffer Submissions** | 2,105 | 801 | 231 |
| **Ring Buffer Reserve Drops** | **0 (0.00%)** | **1,301 (61.89%)** | **1,873 (89.02%)** |
| **Theoretical Buffer Capacity** | 48,770 events | 762 events | 190 events |
| **Accepted Records During Pause**| 2,105 (absorbed) | **762 events** | **190 events** |
| **Accepted Records Post-Pause** | 0 | 39 events | 41 events |
| **Userspace Decoded Records** | 2,105 | 801 | 231 |
| **Telemetry Delivery Rate** | **100.00%** | **100.00%** | **100.00%** |
| **Conservation Invariant** | $2,105 = 2,105 + 0$ | $2,102 = 801 + 1,301$ | $2,104 = 231 + 1,873$ |
| **Mathematical Precision** | **Exact (100.0%)** | **Exact (100.0%)** | **Exact (100.0%)** |

### Conclusions:
1. **Capacity Exactness:** When the userspace reader freezes, kernel buffer exhaustion strictly follows the theoretical capacity bounds ($190$ and $762$ events).
2. **Conservation Enforcement:** $\text{Hooks} = \text{Submissions} + \text{Drops}$ holds across all buffer configurations with zero uncounted events.
3. **Recovery Fidelity:** Resumed readers drain all remaining events without queue corruption or daemon failure.
