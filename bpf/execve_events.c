#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* Metrics indexes for array map */
#define CG_METRIC_HOOK_CALLS        0
#define CG_METRIC_RB_RESERVE_DROPS  1
#define CG_METRIC_RB_SUBMITTED      2
#define CG_METRIC_CGROUP_MAP_FAILS  3
#define CG_METRIC_MAX_INDEX         4

/* Event flags */
#define CG_FLAG_START_TIME_ESTIMATED        (1 << 0)
#define CG_FLAG_PARENT_START_TIME_ESTIMATED (1 << 1)
#define CG_FLAG_PATH_TRUNCATED              (1 << 2)
#define CG_FLAG_COMM_TRUNCATED              (1 << 3)
#define CG_FLAG_EXECVEAT                    (1 << 4)
#define CG_FLAG_AT_EMPTY_PATH               (1 << 5)
#define CG_FLAG_COMMITTED_EXEC              (1 << 6)
#define CG_FLAG_EXEC_FAILED                 (1 << 7)
#define CG_FLAG_CGROUP_MIGRATED             (1 << 8)
#define CG_FLAG_SETUID_EXEC                 (1 << 9)

#define CG_AT_EMPTY_PATH                    0x1000
#define CG_AT_FDCWD                         (-100)

/* Enriched kernel exec event structure: 360 bytes, 64-bit aligned */
struct exec_event {
    __u64 timestamp_ns;         /* Monotonic timestamp of execution (offset 0) */
    __u64 cgroup_id;            /* 64-bit cgroup v2 inode (offset 8) */
    __u64 parent_cgroup_id;     /* 64-bit parent cgroup v2 inode (offset 16) */
    __u64 seq_num;              /* Monotonic sequence number (offset 24) */
    __u64 start_time_ns;        /* Thread-group leader process start time (offset 32) */
    __u64 parent_start_time_ns; /* Parent thread-group leader start time (offset 40) */

    __u32 tid;                  /* Thread ID of executing thread (offset 48) */
    __u32 tgid;                 /* Process ID (Thread Group ID) (offset 52) */
    __u32 parent_tgid;          /* Parent Process ID (PPID) (offset 56) */
    __u32 uid;                  /* User ID (offset 60) */
    __u32 gid;                  /* Group ID (offset 64) */
    __u32 flags;                /* Flags: estimated start, truncated, execveat, committed, failed (offset 68) */

    __s32 dfd;                  /* Directory file descriptor for execveat (-100 for AT_FDCWD) (offset 72) */
    __u32 at_flags;             /* Flags for execveat (e.g. AT_EMPTY_PATH = 0x1000) (offset 76) */
    __s32 exit_code;            /* Syscall return code (0 for success, negative errno on failure) (offset 80) */
    __u32 euid;                 /* Effective UID after execution (offset 84) */

    char comm[16];              /* Command name (offset 88) */
    char filename[256];         /* Executable pathname (offset 104) */
};

/* In-flight execution attempt tracked between enter and commit/exit */
struct exec_attempt {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u64 parent_cgroup_id;
    __u64 start_time_ns;
    __u64 parent_start_time_ns;

    __u32 tid;
    __u32 tgid;
    __u32 parent_tgid;
    __u32 uid;
    __u32 gid;
    __u32 flags;

    __s32 dfd;
    __u32 at_flags;
    __u32 pad;

    char comm[16];
    char filename[256];
};

/* Primary ring buffer for high-throughput event transmission */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MB ring buffer default */
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

/* Active execution attempts table (LRU map avoids leaks on thread termination) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64); /* pid_tgid */
    __type(value, struct exec_attempt);
} active_exec_attempts SEC(".maps");

/* Per-CPU scratchpad to construct exec_attempt without exceeding 512-byte stack limit */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct exec_attempt);
} attempt_scratch SEC(".maps");

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
        return;
    }

    __u64 init_val = 1;
    long ret = bpf_map_update_elem(&cgroup_event_counters, &cgroup_id, &init_val, BPF_NOEXIST);
    if (ret == 0) {
        return;
    }

    /* Another core may have inserted concurrently under BPF_NOEXIST; re-lookup and atomically increment */
    val = bpf_map_lookup_elem(&cgroup_event_counters, &cgroup_id);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        increment_metric(CG_METRIC_CGROUP_MAP_FAILS);
    }
}

static __always_inline void populate_process_metadata(
    struct exec_attempt *att,
    __u64 pid_tgid,
    __u64 uid_gid,
    __u64 cgroup_id
) {
    struct task_struct *task;
    struct task_struct *leader;
    struct task_struct *parent;
    struct task_struct *parent_leader;
    __u64 start_time;
    __u64 parent_start_time = 0;
    __u64 parent_cgroup_id = 0;
    __u32 parent_tgid = 0;
    __u32 flags = 0;

    task = (struct task_struct *)bpf_get_current_task();
    leader = BPF_CORE_READ(task, group_leader);
    if (!leader)
        leader = task;

    parent = BPF_CORE_READ(task, real_parent);
    parent_leader = NULL;
    if (parent) {
        parent_leader = BPF_CORE_READ(parent, group_leader);
        if (!parent_leader)
            parent_leader = parent;
    }

    start_time = BPF_CORE_READ(leader, start_time);
    if (start_time == 0) {
        start_time = bpf_ktime_get_ns();
        flags |= CG_FLAG_START_TIME_ESTIMATED;
    }

    if (parent_leader) {
        parent_start_time = BPF_CORE_READ(parent_leader, start_time);
        parent_tgid = BPF_CORE_READ(parent_leader, tgid);
        parent_cgroup_id = BPF_CORE_READ(parent_leader, cgroups, dfl_cgrp, kn, id);
        if (parent_start_time == 0) {
            flags |= CG_FLAG_PARENT_START_TIME_ESTIMATED;
        }
    }

    att->timestamp_ns = bpf_ktime_get_ns();
    att->cgroup_id = cgroup_id;
    att->parent_cgroup_id = parent_cgroup_id;
    att->start_time_ns = start_time;
    att->parent_start_time_ns = parent_start_time;

    att->tid = (__u32)pid_tgid;
    att->tgid = (__u32)(pid_tgid >> 32);
    att->parent_tgid = parent_tgid;

    att->uid = (__u32)uid_gid;
    att->gid = (__u32)(uid_gid >> 32);
    att->flags = flags;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int cg_execve_events(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    struct exec_attempt *att;
    __u64 pid_tgid;
    __u64 uid_gid;
    __u64 cgroup_id;
    long len;

    /* 1. Account for kernel hook invocation */
    increment_metric(CG_METRIC_HOOK_CALLS);

    cgroup_id = bpf_get_current_cgroup_id();
    increment_cgroup_counter(cgroup_id);

    att = bpf_map_lookup_elem(&attempt_scratch, &zero);
    if (!att)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();

    populate_process_metadata(att, pid_tgid, uid_gid, cgroup_id);

    att->dfd = CG_AT_FDCWD;
    att->at_flags = 0;
    att->pad = 0;

    bpf_get_current_comm(att->comm, sizeof(att->comm));
    if (att->comm[14] != '\0') {
        att->flags |= CG_FLAG_COMM_TRUNCATED;
    }

    len = bpf_probe_read_user_str(
        att->filename,
        sizeof(att->filename),
        (const char *)ctx->args[0]
    );
    if (len < 0) {
        att->filename[0] = '\0';
    } else if (len >= sizeof(att->filename)) {
        att->filename[sizeof(att->filename) - 1] = '\0';
        att->flags |= CG_FLAG_PATH_TRUNCATED;
    }

    bpf_map_update_elem(&active_exec_attempts, &pid_tgid, att, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int cg_execveat_events(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    struct exec_attempt *att;
    __u64 pid_tgid;
    __u64 uid_gid;
    __u64 cgroup_id;
    long len;

    /* 1. Account for kernel hook invocation */
    increment_metric(CG_METRIC_HOOK_CALLS);

    cgroup_id = bpf_get_current_cgroup_id();
    increment_cgroup_counter(cgroup_id);

    att = bpf_map_lookup_elem(&attempt_scratch, &zero);
    if (!att)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();

    populate_process_metadata(att, pid_tgid, uid_gid, cgroup_id);

    att->dfd = (__s32)ctx->args[0];
    att->at_flags = (__u32)ctx->args[4];
    att->pad = 0;
    att->flags |= CG_FLAG_EXECVEAT;

    if (att->at_flags & CG_AT_EMPTY_PATH) {
        att->flags |= CG_FLAG_AT_EMPTY_PATH;
    }

    bpf_get_current_comm(att->comm, sizeof(att->comm));
    if (att->comm[14] != '\0') {
        att->flags |= CG_FLAG_COMM_TRUNCATED;
    }

    len = bpf_probe_read_user_str(
        att->filename,
        sizeof(att->filename),
        (const char *)ctx->args[1]
    );
    if (len < 0) {
        att->filename[0] = '\0';
    } else if (len >= sizeof(att->filename)) {
        att->filename[sizeof(att->filename) - 1] = '\0';
        att->flags |= CG_FLAG_PATH_TRUNCATED;
    }

    bpf_map_update_elem(&active_exec_attempts, &pid_tgid, att, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int cg_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct exec_attempt *att;
    struct exec_event *event;

    att = bpf_map_lookup_elem(&active_exec_attempts, &pid_tgid);
    if (!att) {
        return 0;
    }

    /* Attempt Ring Buffer reservation */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_metric(CG_METRIC_RB_RESERVE_DROPS);
        bpf_map_delete_elem(&active_exec_attempts, &pid_tgid);
        return 0;
    }

    event->timestamp_ns = att->timestamp_ns;
    event->cgroup_id = att->cgroup_id;
    event->parent_cgroup_id = att->parent_cgroup_id;
    event->seq_num = next_seq_num();
    event->start_time_ns = att->start_time_ns;
    event->parent_start_time_ns = att->parent_start_time_ns;

    event->tid = att->tid;
    event->tgid = att->tgid;
    event->parent_tgid = att->parent_tgid;

    event->uid = att->uid;
    event->gid = att->gid;
    event->flags = att->flags | CG_FLAG_COMMITTED_EXEC;

    struct task_struct *cur_task = (struct task_struct *)bpf_get_current_task();
    __u32 euid = BPF_CORE_READ(cur_task, cred, euid.val);
    event->euid = euid;
    if (euid != event->uid) {
        event->flags |= CG_FLAG_SETUID_EXEC;
    }

    event->dfd = att->dfd;
    event->at_flags = att->at_flags;
    event->exit_code = 0;

    /* Get newly executed binary comm */
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    if (event->comm[14] != '\0') {
        event->flags |= CG_FLAG_COMM_TRUNCATED;
    }

    /* If filename was empty (e.g. AT_EMPTY_PATH), read kernel-resolved name from tracepoint */
    if (att->filename[0] == '\0') {
        bpf_probe_read_kernel_str(
            event->filename,
            sizeof(event->filename),
            (void *)ctx + (ctx->__data_loc_filename & 0xffff)
        );
    } else {
        __builtin_memcpy(event->filename, att->filename, sizeof(event->filename));
    }

    increment_metric(CG_METRIC_RB_SUBMITTED);
    bpf_ringbuf_submit(event, 0);

    bpf_map_delete_elem(&active_exec_attempts, &pid_tgid);
    return 0;
}

static __always_inline int handle_exec_exit(__u64 pid_tgid, long ret)
{
    struct exec_attempt *att;
    struct exec_event *event;

    if (ret >= 0) {
        /* Success is committed via sched_process_exec; clean up any remaining attempt */
        bpf_map_delete_elem(&active_exec_attempts, &pid_tgid);
        return 0;
    }

    /* Syscall returned an error: capture failed execution attempt */
    att = bpf_map_lookup_elem(&active_exec_attempts, &pid_tgid);
    if (!att) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_metric(CG_METRIC_RB_RESERVE_DROPS);
        bpf_map_delete_elem(&active_exec_attempts, &pid_tgid);
        return 0;
    }

    event->timestamp_ns = att->timestamp_ns;
    event->cgroup_id = att->cgroup_id;
    event->parent_cgroup_id = att->parent_cgroup_id;
    event->seq_num = next_seq_num();
    event->start_time_ns = att->start_time_ns;
    event->parent_start_time_ns = att->parent_start_time_ns;

    event->tid = att->tid;
    event->tgid = att->tgid;
    event->parent_tgid = att->parent_tgid;

    event->uid = att->uid;
    event->gid = att->gid;
    event->flags = att->flags | CG_FLAG_EXEC_FAILED;

    event->dfd = att->dfd;
    event->at_flags = att->at_flags;
    event->exit_code = (__s32)ret;
    event->euid = att->uid;

    __builtin_memcpy(event->comm, att->comm, sizeof(event->comm));
    __builtin_memcpy(event->filename, att->filename, sizeof(event->filename));

    increment_metric(CG_METRIC_RB_SUBMITTED);
    bpf_ringbuf_submit(event, 0);

    bpf_map_delete_elem(&active_exec_attempts, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int cg_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    return handle_exec_exit(pid_tgid, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int cg_execveat_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    return handle_exec_exit(pid_tgid, ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";
