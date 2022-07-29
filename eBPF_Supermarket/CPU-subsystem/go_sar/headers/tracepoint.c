// +build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") countMap = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 2,
};

struct bpf_map_def SEC("maps") enterTime = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 4096,
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
		u32 key = 0;
		u64 initval = 1, *valp;

		valp = bpf_map_lookup_elem(&countMap, &key);
		if (!valp) {
			// 没有找到表项
			bpf_map_update_elem(&countMap, &key, &initval, BPF_ANY);
			return 0;
		}

		__sync_fetch_and_add(valp, 1);
	}

	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int sched_process_fork() {
	u32 key = 1;
	u64 initval = 1, *valp;

	valp = bpf_map_lookup_elem(&countMap, &key);
	if (!valp) {
		// 没有找到表项
		bpf_map_update_elem(&countMap, &key, &initval, BPF_ANY);
		return 0;
	}

	__sync_fetch_and_add(valp, 1);
	return 0;
}

// SEC("tracepoint/syscalls/sys_enter")
// int sys_enter() {
// 	u32 pid = bpf_get_current_pid_tgid();
// 	u64 time = bpf_ktime_get_ns();
// 	bpf_map_update_elem(&enterTime, &pid, &time, BPF_ANY);
// }

// SEC("tracepoint/syscalls/sys_exit")
// int sys_exit() {
	
// }