// +build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1024,
};

typedef int pid_t;

struct sched_info {
	u64 pad;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int sched_switch(struct sched_info *info) {
	if (info->prev_pid != info->next_pid) {
		u32 key = info->prev_pid;
		u64 initval = 1, *valp;

		valp = bpf_map_lookup_elem(&kprobe_map, &key);
		if (!valp) {
			// 没有找到表项
			bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
			return 0;
		}

		__sync_fetch_and_add(valp, 1);
	}

	return 0;
}
