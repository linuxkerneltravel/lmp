// +build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

typedef int pid_t;

struct migrate_value {
	u64 time;
	pid_t pid;
	int prio;
	int orig_cpu;
	int dest_cpu;
};

struct bpf_map_def SEC("maps") queue = {
	.type        = BPF_MAP_TYPE_HASH,
	// QUEUE不需要key
	.key_size	 = sizeof(u32),
	.value_size  = sizeof(struct migrate_value),
	.max_entries = 4096,
};

struct bpf_map_def SEC("maps") kprobe_map = {
	.type			= BPF_MAP_TYPE_ARRAY,
	.key_size		= sizeof(u32),
	.value_size		= sizeof(u64),
	.max_entries	= 1,
};

struct migrate_info {
	u64 pad;
	char comm[16];
	pid_t pid;
	int prio;
	int orig_cpu;
	int dest_cpu;
};

SEC("tracepoint/sched/sched_migrate_task")
int sched_switch(struct migrate_info *info) {
	u32 key = 0;
	u64 initval = 1, *valp;

	valp = bpf_map_lookup_elem(&kprobe_map, &key);
	if (!valp) {
		// 没有找到表项
		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
		return 0;
	}

	__sync_fetch_and_add(valp, 1);

	u64 time = bpf_ktime_get_ns();
	struct migrate_value val;
	val.time = time;
	val.pid = info->pid;
	val.prio = info->prio;
	val.orig_cpu = info->orig_cpu;
	val.dest_cpu = info->dest_cpu;
	bpf_map_update_elem(&queue, valp, &val, BPF_ANY); // 写入migrate值结构体
	return 0;
}
