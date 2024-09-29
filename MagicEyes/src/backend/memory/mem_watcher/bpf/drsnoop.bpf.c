#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mem_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Define BPF maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, u64);
    __type(value, struct val_t);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} vm_stat_map SEC(".maps");

struct trace_event_raw_mm_vmscan_direct_reclaim_end_template___x {
    long unsigned int nr_reclaimed;
} __attribute__((preserve_access_index));

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int trace_mm_vmscan_direct_reclaim_begin(void *ctx) {
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u64 *vm_stat_addr;
    __u32 key = 0;  // 使用与用户态相同的键值

    // Capture start timestamp and process information
    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.id = id;
        val.ts = bpf_ktime_get_ns();
        // Retrieve the vm_stat address from the map
        vm_stat_addr = bpf_map_lookup_elem(&vm_stat_map, &key);
        if (vm_stat_addr) {
            bpf_probe_read_kernel(&val.vm_stat, sizeof(val.vm_stat), (const void *)*vm_stat_addr);
        }
        else {
            bpf_printk("vm_stat address not found in map\n");
        }
        bpf_map_update_elem(&start, &id, &val, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int trace_mm_vmscan_direct_reclaim_end(void *ctx) {
    struct trace_event_raw_mm_vmscan_direct_reclaim_end_template___x *args = ctx;

    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t *data;
    u64 ts = bpf_ktime_get_ns();
    
    valp = bpf_map_lookup_elem(&start, &id);
    if (!valp) {
        bpf_printk("No start record found for PID %llu\n", id >> 32);
        return 0;
    }

    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
    if (!data) {
        bpf_printk("Failed to reserve space in ringbuf\n");
        return 0;
    }

    data->id = valp->id;
    data->delta = ts - valp->ts;
    data->ts = ts / 1000;
    bpf_probe_read_kernel(&data->name, sizeof(data->name), valp->name);
    bpf_probe_read_kernel(&data->vm_stat, sizeof(data->vm_stat), valp->vm_stat);
    data->nr_reclaimed = BPF_CORE_READ(args, nr_reclaimed);

    bpf_ringbuf_submit(data, 0);
    bpf_map_delete_elem(&start, &id);
    
    return 0;
}
