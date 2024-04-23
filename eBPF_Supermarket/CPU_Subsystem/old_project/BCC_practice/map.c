#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#define TASK_IDLE			0x0402

struct rq {
	raw_spinlock_t lock;
	unsigned int nr_running;
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
	unsigned int numa_migrate_on;
	long unsigned int last_blocked_load_update_tick;
	unsigned int has_blocked_load;
};

struct curState {
	long int task_state;
	u32 task_pid;
	u32 pad;
};

typedef int pid_t;
BPF_ARRAY(countMap, u64, 2);
	// 一个表格，第0项为上下文切换次数，第1项为总共新建进程个数
BPF_ARRAY(rq_map, struct rq, 1);
BPF_HASH(procStartTime, pid_t, u64, 4096);

BPF_ARRAY(idleLastTime, u64, 1);
BPF_PERCPU_ARRAY(runqlen, u64, 1);

BPF_HASH(softirqCpuEnterTime, u32, u64, 4096);
BPF_ARRAY(softirqLastTime, u64, 1);

BPF_HASH(irqCpuEnterTime, u32, u64, 4096);
BPF_ARRAY(irqLastTime, u64, 1);

BPF_HASH(idlePid, u32, u64, 32); // 运行类型为TASK_IDLE的进程
BPF_PERCPU_ARRAY(curTask, u64, 1);

struct __softirq_info {
	u64 pad;
	u32 vec;
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

struct __irq_info {
	u64 pad;
	u32 irq;
};

// 获取进程切换数
int trace_sched_switch(struct cswch_args *info) {
	if (info->prev_pid != info->next_pid) {
		u32 key = 0;
		u64 *valp, delta, cur;
		struct task_struct *ts;

		pid_t pid = info->next_pid;
		u64 time = bpf_ktime_get_ns();
		// 新建或修改一项进程的起始时间
		procStartTime.update(&pid, &time);

		// 更新当前的进程状态为正在执行next_prev
		// 必须确保结构体里没有编译器的自动pad，可通过自己加pad解决。这时pad一定要初始化
		// 当前已经不用结构体了!
		// 参阅: https://houmin.cc/posts/f9d032dd/
		cur = info->next_pid;
		curTask.update(&key, &cur);

		pid = info->prev_pid;
		// 计算空闲时间占比
		valp = procStartTime.lookup(&pid); // *valp储存prev进程的开始时间
		ts = bpf_get_current_task(); // 当前的ts结构体指向prev

		// 是空闲的进程
		if (valp && ts->state == TASK_IDLE) {
			// 捕获到空闲进程
			u64 *valq;
			valq = idlePid.lookup(&pid);
			
			if (!valq) { // 未记录此进程，现在记录
				u64 initval = 1;
				idlePid.update(&pid, &initval);
			}

			delta = time - *valp;
			pid = 0;
			valp = idleLastTime.lookup(&pid);
			if (!valp) {
				idleLastTime.update(&pid, &delta);
			} else {
				*valp += delta;
			}
		}

		// 记录上下文切换的总次数
		valp = countMap.lookup(&key);
		if (!valp) {
			// 没有找到表项
			u64 initval = 1;
			countMap.update(&key, &initval);
			return 0;
		}

		*valp += 1;
	}

	return 0;
}

// 两个CPU各自会产生一个调用，这正好方便我们使用
int tick_update() {
	// 刷新procStartTime，同时更新到idleLastTime
	u32 key = 0;
	u64 *valp, pid, time, delta = 0, *cur_pid;
	struct task_struct *ts;

	time = bpf_ktime_get_ns();
	cur_pid = curTask.lookup(&key);
	ts = bpf_get_current_task();

	// 表示当前已经记录存在进程在执行，并且是空闲的进程
	if (cur_pid && ts->pid == cur_pid && ts->state == TASK_IDLE) {
		valp = procStartTime.lookup(&pid);
		if (valp) { // 只在有表项的时候更新
			delta = time - *valp;
			*valp = time;
		}

		// 更新idleTime
		valp = idleLastTime.lookup(&key);
		if (valp) *valp += delta;
		else idleLastTime.update(&key, &delta);
	}

	return 0;
}

// softirq入口函数
// SEC("tracepoint/irq/softirq_entry")
int trace_softirq_entry(struct __softirq_info *info) {
	u32 key = info->vec;
	u64 val = bpf_ktime_get_ns();

	softirqCpuEnterTime.update(&key, &val);
	return 0;
}

// softirq出口函数
// SEC("tracepoint/irq/softirq_exit")
int trace_softirq_exit(struct __softirq_info *info) {
	u32 key = info->vec;
	u64 now = bpf_ktime_get_ns(), *valp = 0;

	valp = softirqCpuEnterTime.lookup(&key);
	if (valp) {
		// 找到表项
		u64 last_time = now - *valp;
		u32 key0 = 0;
		valp = softirqLastTime.lookup(&key0);

		if (!valp) {
			softirqLastTime.update(&key0, &last_time);
		} else {
			*valp += last_time;
		}
	}
	return 0;
}

// 获取新建进程数
// SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork() {
	u32 key = 1;
	u64 initval = 1, *valp;

	valp = countMap.lookup(&key);
	if (!valp) {
		// 没有找到表项
		countMap.update(&key, &initval);
		return 0;
	}

	*valp += 1;
	return 0;
}

// 获取运行队列长度
// SEC("kprobe/update_rq_clock")
int update_rq_clock(struct pt_regs *ctx) {
	u32 key     = 0;
	u32 rqKey	= 0;
	struct rq *p_rq = 0;

	p_rq = (struct rq *)rq_map.lookup(&rqKey);
	if (!p_rq) { // 针对map表项未创建的时候，map表项之后会自动创建并初始化
		return 0;
	}

	bpf_probe_read_kernel(p_rq, sizeof(struct rq), (void *)PT_REGS_PARM1(ctx));
	u64 val = p_rq->nr_running;
	
	runqlen.update(&key, &val);
	return 0;
}

// SEC("tracepoint/irq/irq_handler_entry")
int trace_irq_handler_entry(struct __irq_info *info) {
	u32 key = info->irq;
	u64 val = bpf_ktime_get_ns();

	irqCpuEnterTime.update(&key, &val);
	return 0;
}

// SEC("tracepoint/irq/irq_handler_exit")
int trace_irq_handler_exit(struct __irq_info *info) {
	u32 key = info->irq;
	u64 now = bpf_ktime_get_ns(), *valp = 0;

	valp = irqCpuEnterTime.lookup(&key);
	if (valp) {
		// 找到表项
		u64 last_time = now - *valp;
		u32 key0 = 0;
		valp = irqLastTime.lookup(&key0);

		if (!valp) {
			irqLastTime.update(&key0, &last_time);
		} else {
			*valp += last_time;
		}
	}
	return 0;
}

