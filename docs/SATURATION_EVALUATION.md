# ContainerGuard: Controlled Ring Buffer Saturation and Telemetry Boundary Evaluation (Phase H.2)

## 1. Experimental Methodology and Rationale

In Phase H, ContainerGuard demonstrated 100% telemetry delivery across workloads up to 25,000 events without any ring buffer reservation drops. While this established high throughput scalability (up to 1,923 hooks/sec), it did **not** identify the kernel ring buffer saturation threshold.

The objective of Phase H.2 is to scientifically define and empirically demonstrate the **telemetry loss boundary**:
1. What workload and configuration cause kernel-side buffer drops (`bpf_ringbuf_reserve` failures)?
2. How does ContainerGuard account for dropped telemetry when the userspace reader experiences backpressure?
3. How does the sequence gap detector respond to genuine kernel-side loss?
4. How quickly does the system recover once transient backpressure ceases?

---

## 2. Theoretical Memory Model & Buffer Sizing

Each execution event record (`struct exec_event`) defined in `bpf/execve_events.c` has the following memory layout:
* `timestamp_ns`: 8 bytes
* `cgroup_id`: 8 bytes
* `seq_num`: 8 bytes
* `start_time_ns`: 8 bytes
* `parent_start_time_ns`: 8 bytes
* `tid`, `tgid`, `parent_tgid`, `uid`, `gid`, `flags`: $6 \times 4 = 24$ bytes
* `comm[16]`: 16 bytes
* `filename[256]`: 256 bytes
* **Total struct size:** 336 bytes
* **BPF Ring Buffer frame overhead:** 8 bytes (header + length/flags)
* **Total wire footprint per event:** **344 bytes**

### Capacity Table Across Tested Configurations:
$$\text{Max Buffered Events} \approx \frac{\text{Ring Buffer Size (bytes)}}{344\text{ bytes/event}}$$

| Ring Buffer Size | Size in Bytes | Max Buffered Events (Theoretical Limit) | Saturation Event Threshold |
|---|---|---|---|
| **64 KiB** | 65,536 bytes | $\approx 190$ events | $\ge 200$ unconsumed events |
| **256 KiB** | 262,144 bytes | $\approx 762$ events | $\ge 800$ unconsumed events |
| **1,024 KiB (1 MiB)** | 1,048,576 bytes | $\approx 3,048$ events | $\ge 3,200$ unconsumed events |
| **16,384 KiB (16 MiB Baseline)** | 16,777,216 bytes | $\approx 48,770$ events | $\ge 50,000$ unconsumed events |

---

## 3. Experimental Test Matrix for Phase H.2

### Suite 1: Capacity Sensitivity Under Concurrency (Zero Backpressure)
Tests whether small ring buffers can sustain multi-core bursts when the userspace consumer is actively draining.
* **Workload:** 8 concurrent container streams $\times$ 250 events = 2,000 events total.
* **Configurations:**
  1. `sat_16mb_8stream`: 16 MiB baseline (`-ringbuf-size-kb 16384`)
  2. `sat_1mb_8stream`: 1 MiB (`-ringbuf-size-kb 1024`)
  3. `sat_256kb_8stream`: 256 KiB (`-ringbuf-size-kb 256`)
  4. `sat_64kb_8stream`: 64 KiB (`-ringbuf-size-kb 64`)

### Suite 2: Induced Userspace Backpressure & Failure Boundary
Artificially pauses userspace ring buffer reader startup by **2 seconds** (`-backpressure-pause-sec 2`) while 4 concurrent streams dispatch **2,000 events** (500 per stream).
* **Configurations:**
  1. `sat_bp_16mb` (16 MiB + 2s pause): Capacity (48,770 events) $\gg$ 2,000 events $\rightarrow$ **Zero loss expected**.
  2. `sat_bp_256kb` (256 KiB + 2s pause): Capacity ($\sim 762$ events) $<$ 2,000 events $\rightarrow$ **$\sim 1,200$ reservation drops expected**.
  3. `sat_bp_64kb` (64 KiB + 2s pause): Capacity ($\sim 190$ events) $\ll$ 2,000 events $\rightarrow$ **$\sim 1,800$ reservation drops expected**.

---

## 4. Execution Protocol

Execute the saturation benchmark suite using the automated test harness:

```bash
# Suite 1: Capacity Sensitivity (8 concurrent streams, 2,000 events)
sudo ./scripts/saturation_test.sh sat_16mb_8stream 16384 0 8 250
sudo ./scripts/saturation_test.sh sat_1mb_8stream   1024  0 8 250
sudo ./scripts/saturation_test.sh sat_256kb_8stream 256  0 8 250
sudo ./scripts/saturation_test.sh sat_64kb_8stream   64  0 8 250

# Suite 2: Userspace Backpressure & Failure Boundary (4 streams, 2,000 events, 2s reader pause)
sudo ./scripts/saturation_test.sh sat_bp_16mb 16384 2 4 500
sudo ./scripts/saturation_test.sh sat_bp_256kb  256 2 4 500
sudo ./scripts/saturation_test.sh sat_bp_64kb    64 2 4 500
```
