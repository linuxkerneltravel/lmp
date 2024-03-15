#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "page_fault.h"

#define INTERVAL_MAX 6U

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned);
	__type(value, u64);
} count_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, u64);
} time_map SEC(".maps");

SEC("kprobe/do_swap_page")
int count_entry(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&time_map, &pid, &ts, BPF_ANY);
	
	return 0;
}

SEC("kretprobe/handle_mm_fault")
int count_end(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 tm = bpf_ktime_get_ns();
	u64 *tsp = bpf_map_lookup_elem(&time_map, &pid);
	
	if (tsp)
		tm -= *tsp;
	else
		return 1;

	unsigned key = tm / 10000000;
	if (key > INTERVAL_MAX - 1)
		key = INTERVAL_MAX - 1;
	
	u64 *value = bpf_map_lookup_elem(&count_map, &key);
	if (value)
		*value += 1;
	else {
		u64 init_value = 1;
		bpf_map_update_elem(&count_map, &key, &init_value, BPF_ANY);
	}	

	bpf_map_delete_elem(&time_map, &pid);

	return 0;
}

char _license[] SEC("license") = "GPL";