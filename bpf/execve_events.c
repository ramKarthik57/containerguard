#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* Metrics indexes for array map */
#define CG_METRIC_HOOK_CALLS        0
#define CG_METRIC_RB_RESERVE_DROPS  1
#define CG_METRIC_RB_SUBMITTED      2
#define CG_METRIC_CGROUP_MAP_FAILS  3
#define CG_METRIC_MAX_INDEX         4

struct exec_event {
    __u64 timestamp_ns;         /* Monotonic timestamp of execution */
    __u64 cgroup_id;            /* 64-bit cgroup v2 inode */
    __u64 seq_num;              /* Monotonic sequence number */
    __u64 start_time_ns;        /* Trustworthy process start time from task_struct */
    __u64 parent_start_time_ns; /* Parent process start time from real_parent */

    __u32 tid;                  /* Thread ID */
    __u32 tgid;                 /* Process ID */
    __u32 parent_tgid;          /* Parent Process ID */
    __u32 uid;                  /* User ID */
    __u32 gid;                  /* Group ID */
    __u32 _pad;                 /* 4-byte padding for 64-byte aligned header */

    char comm[16];              /* Command name */
    char filename[256];         /* Executable pathname */
};

/* Primary ring buffer for high-throughput event transmission */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MB ring buffer */
} events SEC(".maps");

/* Telemetry integrity counters: hook calls, reserve failures, submitted events, map fails */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CG_METRIC_MAX_INDEX);
    __type(key, __u32);
    __type(value, __u64);
} telemetry_counters SEC(".maps");

/* Per-cgroup event counter map for container event accounting */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u64);
} cgroup_event_counters SEC(".maps");

/* Global monotonic sequence generator for loss accounting */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} event_sequence SEC(".maps");

static __always_inline void increment_metric(__u32 metric_idx)
{
    __u64 *counter = bpf_map_lookup_elem(&telemetry_counters, &metric_idx);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline __u64 next_seq_num(void)
{
    __u32 key = 0;
    __u64 *seq = bpf_map_lookup_elem(&event_sequence, &key);
    if (seq) {
        return __sync_fetch_and_add(seq, 1);
    }
    return 0;
}

static __always_inline void increment_cgroup_counter(__u64 cgroup_id)
{
    __u64 *val = bpf_map_lookup_elem(&cgroup_event_counters, &cgroup_id);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u64 init_val = 1;
        long ret = bpf_map_update_elem(&cgroup_event_counters, &cgroup_id, &init_val, BPF_ANY);
        if (ret < 0) {
            increment_metric(CG_METRIC_CGROUP_MAP_FAILS);
        }
    }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int cg_execve_events(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *event;
    struct task_struct *task;
    struct task_struct *parent;
    __u64 pid_tgid;
    __u64 uid_gid;
    __u64 cgroup_id;
    __u64 seq;

    /* 1. Account for every kernel hook invocation */
    increment_metric(CG_METRIC_HOOK_CALLS);

    cgroup_id = bpf_get_current_cgroup_id();
    increment_cgroup_counter(cgroup_id);

    /* 2. Attempt Ring Buffer reservation */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        /* Account for kernel-side drops under buffer pressure */
        increment_metric(CG_METRIC_RB_RESERVE_DROPS);
        return 0;
    }

    seq = next_seq_num();
    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();

    task = (struct task_struct *)bpf_get_current_task();
    parent = BPF_CORE_READ(task, real_parent);

    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = cgroup_id;
    event->seq_num = seq;
    event->start_time_ns = BPF_CORE_READ(task, start_time);
    event->parent_start_time_ns = BPF_CORE_READ(parent, start_time);

    event->tid = (__u32)pid_tgid;
    event->tgid = (__u32)(pid_tgid >> 32);
    event->parent_tgid = BPF_CORE_READ(parent, tgid);

    event->uid = (__u32)uid_gid;
    event->gid = (__u32)(uid_gid >> 32);
    event->_pad = 0;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    if (bpf_probe_read_user_str(
        event->filename,
        sizeof(event->filename),
        (const char *)ctx->args[0]
    ) < 0) {
        event->filename[0] = '\0';
    }

    /* 3. Account for successful submission */
    increment_metric(CG_METRIC_RB_SUBMITTED);
    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
