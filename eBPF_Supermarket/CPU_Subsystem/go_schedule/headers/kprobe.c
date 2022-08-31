// +build ignore
#include "vmlinux.h"
#include "bpf_helper_defs.h"
#define __TARGET_ARCH_x86
#include "bpf_tracing.h"

#define SEC(name) \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")	    \
	__attribute__((section(name), used))				    \
	_Pragma("GCC diagnostic pop")

/*
 * Helper structure used by eBPF C program
 * to describe BPF map attributes to libbpf loader
 */
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

// 此数组会自动初始化
struct bpf_map_def SEC("maps") rq_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(struct rq),
	.max_entries = 1,
};

// SEC("kprobe/sys_execve")
// int kprobe_execve() {
// 	u32 key     = 0;
// 	u64 initval = 1, *valp;

// 	valp = bpf_map_lookup_elem(&kprobe_map, &key);
// 	if (!valp) {
// 		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
// 		return 0;
// 	}
// __sync_fetch_and_add(valp, 1);

// 	return 0;
// }


// Version 1.0 watching task_struct(of current task)
// SEC("kprobe/update_rq_clock")
// int kprobe_update_rq_clock(struct rq *rq) {
// 	u32 key     = 0;
// 	u64 initval = 1, *valp;

// 	struct task_struct *task = bpf_get_current_task_btf();
// 	u64 val = task->se.cfs_rq->nr_running;
// 	// u64 val = task->pid;

// 	bpf_map_update_elem(&kprobe_map, &key, &val, BPF_ANY);

// 	return 0;
// }

SEC("kprobe/update_rq_clock")
int kprobe_update_rq_clock(struct pt_regs *ctx) {
	u32 key     = 0;
	u64 initval = 1;
	struct rq *p_rq;

	p_rq = (struct rq *)bpf_map_lookup_elem(&rq_map, &key);
	if (!p_rq) { // 针对map表项未创建的时候，map表项之后会自动创建并初始化
		return 0;
	}

	bpf_probe_read_kernel(p_rq, sizeof(struct rq), (void *)PT_REGS_PARM1(ctx));
	u64 val = p_rq->nr_running;

	bpf_map_update_elem(&kprobe_map, &key, &val, BPF_ANY);

	return 0;
}