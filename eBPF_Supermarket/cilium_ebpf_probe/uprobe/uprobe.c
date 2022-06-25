// +build ignore

#include "common.h"

#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct bpf_map_def SEC("maps") uprobe_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

const struct event *unused __attribute__((unused));

SEC("uprobe/http_main")
int uprobe_ahttp_main(struct pt_regs *ctx) {
	struct event event;

	event.pid = bpf_get_current_pid_tgid();

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));


    u32 key     = 0;
    u64 initval = 1, *valp;
    valp = bpf_map_lookup_elem(&uprobe_map, &key);
    if (!valp) {
   		bpf_map_update_elem(&uprobe_map, &key, &initval, BPF_ANY);
   		return 0;
    	}
   	__sync_fetch_and_add(valp, 1);
	return 0;
}