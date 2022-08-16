#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
// #define TASK_IDLE			0x0402

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
BPF_ARRAY(ktLastTime, u64, 1);
BPF_ARRAY(utLastTime, u64, 1);

BPF_PERCPU_ARRAY(runqlen, u64, 1);

BPF_HASH(softirqCpuEnterTime, u32, u64, 4096);
BPF_ARRAY(softirqLastTime, u64, 1);

BPF_HASH(irqCpuEnterTime, u32, u64, 4096);
BPF_ARRAY(irqLastTime, u64, 1);

BPF_HASH(idlePid, u32, u64, 32); // 运行类型为TASK_IDLE的进程
BPF_PERCPU_ARRAY(curTask, u64, 1);

BPF_ARRAY(idleStart, u64, 128);
BPF_ARRAY(symAddr, u64, 1);

struct sysc_state {
	u64 start;
	u64 in_sysc;
	unsigned int flags;
	int pad; // 必须要有的pad项
};
BPF_HASH(syscMap, u32, struct sysc_state, 1024);
BPF_ARRAY(syscTime, u64, 1);


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

struct idleStruct {
	u64 pad;
	int state;
	u32 cpu_id;
};

struct __irq_info {
	u64 pad;
	u32 irq;
};

// 获取进程切换数
int trace_sched_switch(struct cswch_args *info) {
	pid_t prev = info->prev_pid, next = info->next_pid;
	if (prev != next) {
		u32 key = 0;
		u64 *valp, delta, cur;
		struct task_struct *ts;

		pid_t pid = next;
		u64 time = bpf_ktime_get_ns();
		// 新建或修改一项进程的起始时间
		procStartTime.update(&pid, &time);

		/* 更新当前的进程状态为正在执行next_prev
		 * 必须确保结构体里没有编译器的自动pad，可通过自己加pad解决。这时pad一定要初始化
		 * 当前已经不用结构体了!
		 * 参阅: https://houmin.cc/posts/f9d032dd/
		 */
		cur = pid;
		curTask.update(&key, &cur);

		pid = prev;
		// 计算空闲时间占比
		valp = procStartTime.lookup(&pid); // *valp储存prev进程的开始时间
		ts = (struct task_struct *)bpf_get_current_task(); // 当前的ts结构体指向prev

		/* 捕获state为IDLE状态的进程
		if (valp && ts->state == TASK_IDLE) {
			// 捕获到空闲进程
			u64 *valq;
			valq = idlePid.lookup(&pid);
			
			if (!valq) { // 未记录此进程，现在记录
				u64 initval = 1;
				idlePid.update(&pid, &initval);
			}
		}*/

		// 分别处理旧进程和新的进程
		// 旧进程：检查是否处于系统调用中，如果是，就将累积的时间加到syscTime
		struct sysc_state* stat = syscMap.lookup(&(prev));
		if (stat && stat->in_sysc) {
			delta = time - stat->start;
			u64 *valq = syscTime.lookup(&key);
			if (valq) *valq += delta;
			else syscTime.update(&key, &delta);
		}

		// 新进程：检查是否处于系统调用中，如果是，就将其开始时间更新为当前
		stat = syscMap.lookup(&(next));
		if (stat && stat->in_sysc) {
			stat->start = time;
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

#define PF_IDLE			0x00000002	/* I am an IDLE thread */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */

// 计算内核进程运行的时间
int finish_sched(struct pt_regs *ctx, struct task_struct *prev) {
	int pid;
	u64 *valp, time = bpf_ktime_get_ns(), delta;
	struct task_struct *ts = bpf_get_current_task();

	if ((prev->flags & PF_KTHREAD) && prev->pid != 0) {
		// 是内核线程，但不是IDLE-0进程
		pid = prev->pid;
		valp = procStartTime.lookup(&pid);
		if (valp) {
			u32 key = 0;
			delta = time - *valp;

			valp = ktLastTime.lookup(&key);
			if (valp) *valp += delta;
			else ktLastTime.update(&key, &delta);
		}
	} else if (!(prev->flags & PF_KTHREAD)) { // 是用户态进程在执行
		pid = prev->pid;
		valp = procStartTime.lookup(&pid);
		if (valp) {
			u32 key = 0;
			delta = time - *valp;

			valp = utLastTime.lookup(&key);
			if (valp) *valp += delta;
			else utLastTime.update(&key, &delta);
		}
	}
	return 0;
}

// 系统调用进入的信号
int trace_sys_enter() {
	// bpf_trace_printk("sys_enter\n");
	struct task_struct *ts = bpf_get_current_task();
	struct sysc_state sysc;
	u32 pid = ts->pid;
	u64 *valp;

	sysc.start = bpf_ktime_get_ns();
	sysc.flags = ts->flags;
	sysc.in_sysc = 1;
	sysc.pad = 0;
	syscMap.update(&pid, &sysc);
	
	return 0;
}

// 系统调用退出信号
int trace_sys_exit() {
	// bpf_trace_printk("sys_exit\n");
	struct task_struct *ts = bpf_get_current_task();
	struct sysc_state sysc;
	u32 pid = ts->pid, key = 0;
	u64 time = bpf_ktime_get_ns(), delta;
	struct sysc_state *valp;
	
	valp = syscMap.lookup(&pid);
	if (valp) {
		// 既不是内核线程，也不是空闲线程，可以放心记录
		if (!(valp->flags & PF_IDLE) && !(valp->flags & PF_KTHREAD) && valp->in_sysc) {
			delta = time - valp->start;
			u64 *valq = syscTime.lookup(&key);
			if (valq) *valq += delta;
			else syscTime.update(&key, &delta);
		}
	}

	sysc.start = time;
	sysc.flags = ts->flags;
	sysc.in_sysc = 0;
	sysc.pad = 0;
	syscMap.update(&pid, &sysc);
	return 0;
}

// 两个CPU各自会产生一个调用，这正好方便我们使用
int tick_update() {
	u32 key = 0;
	u64 *valp, pid, time, delta = 0, *cur_pid;
	struct task_struct *ts;

	time = bpf_ktime_get_ns();
	cur_pid = curTask.lookup(&key);
	ts = (struct task_struct *)bpf_get_current_task();
	return 0;
}

/* 只有IDLE-0（0号进程）才可以执行cpu_idle的代码 */
int trace_cpu_idle(struct idleStruct *pIDLE) {
	u64 delta, time = bpf_ktime_get_ns();
	u32 key = pIDLE->cpu_id;
	// 按cpuid记录空闲的开始，这十分重要，因为IDLE-0进程可同时运行在两个核上

	if (pIDLE->state == -1) {
		// 结束idle
		u64 *valp = idleStart.lookup(&key);
		if (valp && *valp != 0) {
			delta = time - *valp;
			key = 0;
			valp = idleLastTime.lookup(&key);
			if (valp) *valp += delta;
			else idleLastTime.update(&key, &delta);
		}

		// bpf_trace_printk("End idle.\n");
	} else {
		// 开始idle
		u64 val = time;
		idleStart.update(&key, &val);

		// bpf_trace_printk("Begin idle.\n");
	}
	return 0;
}

// softirq入口函数
// SEC("tracepoint/irq/softirq_entry")
int trace_softirq_entry(struct __softirq_info *info) {
	// bpf_trace_printk("softirq entry %d\n", info->vec);
	u32 key = info->vec;
	u64 val = bpf_ktime_get_ns();

	softirqCpuEnterTime.update(&key, &val);
	return 0;
}

// softirq出口函数
// SEC("tracepoint/irq/softirq_exit")
int trace_softirq_exit(struct __softirq_info *info) {
	// bpf_trace_printk("softirq exit %d\n", info->vec);
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
	// bpf_trace_printk("irq entry %d\n", info->irq);
	u32 key = info->irq;
	u64 val = bpf_ktime_get_ns();

	irqCpuEnterTime.update(&key, &val);
	return 0;
}

// SEC("tracepoint/irq/irq_handler_exit")
int trace_irq_handler_exit(struct __irq_info *info) {
	// bpf_trace_printk("irq exit %d\n", info->irq);
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

