#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct trace_event_raw_sys_enter {
    unsigned long long common;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int cg_execve_probe(struct trace_event_raw_sys_enter *ctx)
{
    (void)ctx;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
