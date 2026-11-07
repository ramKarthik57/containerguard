#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} execve_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int cg_execve_probe(void *ctx)
{
    __u32 key = 0;
    __u64 *count;

    (void)ctx;

    count = bpf_map_lookup_elem(&execve_count, &key);

    if (count)
        __sync_fetch_and_add(count, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
