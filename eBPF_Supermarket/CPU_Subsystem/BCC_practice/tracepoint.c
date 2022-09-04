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
#define TASK_IDLE			0x0402

struct bpf_map_def SEC("maps") countMap = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 4,
};

// 此数组会自动初始化
struct bpf_map_def SEC("maps") rq_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(struct rq),
	.max_entries = 1,
};

typedef int pid_t;

struct bpf_map_def SEC("maps") procStartTime = {
	.type		 = BPF_MAP_TYPE_HASH,
	.key_size	 = sizeof(pid_t),
	.value_size	 = sizeof(u64), // time
	.max_entries = 4096,
};

struct bpf_map_def SEC("maps") procLastTime = {
	.type		 = BPF_MAP_TYPE_ARRAY,
	.key_size	 = sizeof(u32),
	.value_size	 = sizeof(u64), // time
	.max_entries = 1,
};

struct cswch_args {
	u64 pad;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
};

// 获取进程切换数
SEC("tracepoint/sched/sched_switch")
int sched_switch(struct cswch_args *info) {
	if (info->prev_pid != info->next_pid) {
		u32 key = 0;
		u64 initval = 1, *valp, delta;
		struct task_struct *ts;

		pid_t pid = info->prev_pid;
		u64 time = bpf_ktime_get_ns();

		bpf_map_update_elem(&procStartTime, &pid, &time, BPF_ANY);

		pid = info->next_pid;
		// 计算空闲时间占比
		valp = bpf_map_lookup_elem(&procStartTime, &pid);
		ts = bpf_get_current_task_btf();
		if (valp && ts->state == TASK_IDLE) {
			delta = time - *valp;
			pid = 0;
			valp = bpf_map_lookup_elem(&procLastTime, &pid);
			if (!valp) {
				bpf_map_update_elem(&procLastTime, &pid, &delta, BPF_ANY);
			} else {
				*valp += delta;
			}
		}

		// 记录上下文切换的总次数
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

// 获取新建进程数
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

struct bpf_map_def SEC("maps") runqlen = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

// 获取运行队列长度
SEC("kprobe/update_rq_clock")
int update_rq_clock(struct pt_regs *ctx) {
	u32 key     = 0;
	u32 rqKey	= 0;
	struct rq *p_rq;

	p_rq = (struct rq *)bpf_map_lookup_elem(&rq_map, &rqKey);
	if (!p_rq) { // 针对map表项未创建的时候，map表项之后会自动创建并初始化
		return 0;
	}

	bpf_probe_read_kernel(p_rq, sizeof(struct rq), (void *)PT_REGS_PARM1(ctx));
	u64 val = p_rq->nr_running;

	bpf_map_update_elem(&runqlen, &key, &val, BPF_ANY);

	return 0;
}

struct bpf_map_def SEC("maps") irqCpuEnterTime = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 4096,
};

struct __irq_info {
	u64 pad;
	u32 irq;
};

struct bpf_map_def SEC("maps") IrqLastTime = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

SEC("tracepoint/irq/irq_handler_entry")
int irq_handler_entry(struct __irq_info *info) {
	u32 key = info->irq;
	u64 val = bpf_ktime_get_ns();

	bpf_map_update_elem(&irqCpuEnterTime, &key, &val, BPF_ANY);
	return 0;
}

SEC("tracepoint/irq/irq_handler_exit")
int irq_handler_exit(struct __irq_info *info) {
	u32 key = info->irq;
	u64 now = bpf_ktime_get_ns(), *valp = 0;

	valp = bpf_map_lookup_elem(&irqCpuEnterTime, &key);
	if (valp) {
		// 找到表项
		u64 last_time = now - *valp;
		u32 key0 = 0;
		valp = bpf_map_lookup_elem(&IrqLastTime, &key0);

		if (!valp) {
			bpf_map_update_elem(&IrqLastTime, &key0, &last_time, BPF_ANY);
		} else {
			*valp += last_time;
		}
	}
	return 0;
}

struct __softirq_info {
	u64 pad;
	u32 vec;
};

struct bpf_map_def SEC("maps") softirqCpuEnterTime = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 4096,
};

struct bpf_map_def SEC("maps") SoftirqLastTime = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

SEC("tracepoint/irq/softirq_entry")
int softirq_entry(struct __softirq_info *info) {
	u32 key = info->vec;
	u64 val = bpf_ktime_get_ns();

	bpf_map_update_elem(&softirqCpuEnterTime, &key, &val, BPF_ANY);
	return 0;
}

SEC("tracepoint/irq/softirq_exit")
int softirq_exit(struct __softirq_info *info) {
	u32 key = info->vec;
	u64 now = bpf_ktime_get_ns(), *valp = 0;

	valp = bpf_map_lookup_elem(&softirqCpuEnterTime, &key);
	if (valp) {
		// 找到表项
		u64 last_time = now - *valp;
		u32 key0 = 0;
		valp = bpf_map_lookup_elem(&SoftirqLastTime, &key0);

		if (!valp) {
			bpf_map_update_elem(&SoftirqLastTime, &key0, &last_time, BPF_ANY);
		} else {
			*valp += last_time;
		}
	}
	return 0;
}