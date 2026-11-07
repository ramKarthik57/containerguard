#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

struct trace_event_raw_sys_enter {
    __u64 common;
    long id;
    unsigned long args[6];
};

struct exec_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;

    __u32 tid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;

    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int cg_execve_events(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *event;
    __u64 pid_tgid;
    __u64 uid_gid;

    event = bpf_ringbuf_reserve(
        &events,
        sizeof(*event),
        0
    );

    if (!event)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();

    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();

    event->tid = (__u32)pid_tgid;
    event->tgid = pid_tgid >> 32;

    event->uid = (__u32)uid_gid;
    event->gid = uid_gid >> 32;

    bpf_get_current_comm(
        event->comm,
        sizeof(event->comm)
    );

    if (bpf_probe_read_user_str(
        event->filename,
        sizeof(event->filename),
        (const char *)ctx->args[0]
    ) < 0) {
        event->filename[0] = '\0';
    }

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
