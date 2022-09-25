#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
// #define TASK_IDLE			0x0402
#define COUNT_BPF 1

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
// 计数表格，第0项为上下文切换次数，第1项为总共新建进程个数
BPF_ARRAY(countMap, u64, 3);

// 储存运行队列rq的全局变量
BPF_ARRAY(rq_map, struct rq, 1);

// 进程开始时间
BPF_HASH(procStartTime, pid_t, u64, 4096);

// CPU idle持续时间
BPF_ARRAY(idleLastTime, u64, 1);

// kthread持续时间
BPF_ARRAY(ktLastTime, u64, 1);
BPF_ARRAY(utLastTime, u64, 1);
BPF_ARRAY(userTime, u64, 1);

BPF_PERCPU_ARRAY(runqlen, u64, 1);

BPF_TABLE("percpu_hash", u32, u64, softirqCpuEnterTime, 4096);
BPF_ARRAY(softirqLastTime, u64, 1);

BPF_TABLE("percpu_hash", u32, u64, irqCpuEnterTime, 4096);
BPF_ARRAY(irqLastTime, u64, 1);

BPF_HASH(idlePid, u32, u64, 32); // 运行类型为TASK_IDLE的进程，已废弃

BPF_ARRAY(idleStart, u64, 128);
BPF_ARRAY(symAddr, u64, 1);

struct sysc_state {
	u64 start;
	u64 in_sysc;
	unsigned int flags;
	int pad; // 必须要有的pad项
};
BPF_HASH(syscMap, u32, struct sysc_state, 8192);
BPF_ARRAY(syscTime, u64, 1);

BPF_PERCPU_ARRAY(tick_user, u64, 1);

struct user_state {
	u64 start;
	u64 in_user;
};

BPF_HASH(usermodeMap, u32, struct user_state, 8192);

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

/* 之前关于记录sysc时间和用户时间的一系列函数
__always_inline static void on_sys_exit(u64 time) {
	struct task_struct *ts = bpf_get_current_task();

	// Step2：累加进程Syscall时间到syscTime
	struct sysc_state sysc;
	u32 pid = ts->pid, key = 0;
	u64 delta;
	struct sysc_state *valp;
	
	valp = syscMap.lookup(&pid);

	// Step2.5 确保当前进程之前存在记录，且既不是内核线程，也不是空闲线程，可以放心记录
	if (valp && !(valp->flags & PF_IDLE) && !(valp->flags & PF_KTHREAD) && valp->in_sysc) {
		delta = time - valp->start;
		u64 *valq = syscTime.lookup(&key);
		if (valq) *valq += delta;
		else syscTime.update(&key, &delta);
	}

	// Step3: 更新进程的Syscall状态为不在Syscall，并更新进入时间（Optional）
	sysc.start = time;
	sysc.flags = ts->flags;
	sysc.in_sysc = 0;
	sysc.pad = 0;
	syscMap.update(&pid, &sysc);
}

__always_inline static void on_user_enter(u64 time) {
	// Step1: 记录user开始时间，和当前的in_user状态
	struct user_state us;
	struct task_struct *ts = bpf_get_current_task();

	u32 pid = ts->pid;

	us.start = time;
	us.in_user = 1;

	// Step2: 更新usermodeMap
	usermodeMap.update(&pid, &us);
}


// 在sched_switch中记录系统调用花费的时间
__always_inline static void record_sysc(u64 time, pid_t prev, pid_t next) {
	// 分别处理旧进程和新的进程
	// 旧进程：检查是否处于系统调用中，如果是，就将累积的时间加到syscTime
	struct sysc_state* stat = syscMap.lookup(&(prev));
	if (stat && stat->in_sysc) {
		u64 delta = time - stat->start;

		u32 key = 0;
		u64 *valq = syscTime.lookup(&key);
		if (valq) *valq += delta;
		else syscTime.update(&key, &delta);
	}

	// 新进程：检查是否处于系统调用中，如果是，就将其开始时间更新为当前
	stat = syscMap.lookup(&(next));
	if (stat && stat->in_sysc) {
		stat->start = time;
	}
}

__always_inline static void record_user(u64 time, pid_t prev, pid_t next) {
	// 旧进程：检查是否处于用户态，如果是，更新总时间userTime
	struct user_state *us = usermodeMap.lookup(&prev);
	struct sysc_state *sysc = syscMap.lookup(&prev);
	struct task_struct *ts = (struct task_struct *)bpf_get_current_task();

	// 不记录IDLE和KTHREAD的用户态时间
	if (us && us->in_user && !(ts->flags & PF_KTHREAD) && !(ts->flags & PF_IDLE) ) {
		u64 delta = time - us->start;

		u32 key = 0;
		u64 *valp = userTime.lookup(&key);
		if (valp) *valp += delta;
		else userTime.update(&key, &delta);
	}

	// 新进程：检查是否处于用户态，如果是，更新起始时间
	us = usermodeMap.lookup(&next);
	if (us && us->in_user) {
		us->start = time;
	} else if (!us) {
		// 此时进程是第一次执行，需要判断其状态（或者此进程为永不会记录的内核线程）
		// 我们简单地将它的认为是用户态。若误判，当前是sys，那么下一次sys_exit触发用户态进入信号，
		// 那时之前未统计的错当成的用户时间被舍弃

		// * 有必要查询task_struct结构体哪个字段记录了用户进程的状态
		struct user_state _us;
		_us.start = time;
		_us.in_user = 1;
		usermodeMap.update(&next, &_us);
		// bpf_trace_printk("pid %d start.\n", next);
	}
}

*/

// 获取进程切换数
int trace_sched_switch(struct cswch_args *info) {
	if (COUNT_BPF) { // 记录插桩点执行次数
		u32 _key = 2;
		u64 _val = 1;
		u64 *_p = countMap.lookup(&_key);
		if (_p) *_p += 1;
		else countMap.update(&_key, &_val);
	}

	pid_t prev = info->prev_pid, next = info->next_pid;

	if (prev != next) {
		u32 key = 0;
		u64 *valp, delta, cur;
		struct task_struct *ts;

		pid_t pid = next;
		u64 time = bpf_ktime_get_ns();

		// Step1: 记录next进程的起始时间
		procStartTime.update(&pid, &time);

		// Step2: Syscall时间处理
		// record_sysc(time, prev, next);

		// Step3: UserMode时间处理
		// record_user(time, prev, next);

		// Step4: 记录上下文切换的总次数
		valp = countMap.lookup(&key);
		if (!valp) {
			// 没有找到表项
			u64 initval = 1;
			countMap.update(&key, &initval);
		}
		else *valp += 1;
	}

	return 0;
}

#define PF_IDLE			0x00000002	/* I am an IDLE thread */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */

// 计算各进程运行的时间（包括用户态和内核态）
int finish_sched(struct pt_regs *ctx, struct task_struct *prev) {
	if (COUNT_BPF) { // 记录插桩点执行次数
		u32 _key = 2;
		u64 _val = 1;
		u64 *_p = countMap.lookup(&_key);
		if (_p) *_p += 1;
		else countMap.update(&_key, &_val);
	}

	int pid;
	u64 *valp, time = bpf_ktime_get_ns(), delta;
	struct task_struct *ts = bpf_get_current_task();

	// Step1: 记录内核进程（非IDLE）运行时间
	if ((prev->flags & PF_KTHREAD) && prev->pid != 0) {
		pid = prev->pid;
		valp = procStartTime.lookup(&pid);
		if (valp) {
			u32 key = 0;
			delta = time - *valp;

			valp = ktLastTime.lookup(&key);
			if (valp) *valp += delta;
			else ktLastTime.update(&key, &delta);
		}
	// Step2: 记录用户进程运行时间
	} else if (!(prev->flags & PF_KTHREAD) && !(prev->flags & PF_IDLE)) {
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

/*__always_inline static void on_user_exit(u64 time, pid_t pid, u32 flags) {
	// Step1: 查询之前进入用户态的时间，记录退出用户态的时间，并将其累加到userTime
	struct user_state *valp, us;
	u32 key = 0;

	valp = usermodeMap.lookup(&pid);
	if (valp && !(flags & PF_IDLE) && !(flags & PF_KTHREAD) && valp->in_user) {
		u64 delta = time - valp->start;
		u64 *valq = userTime.lookup(&key);
		if (valq) *valq += delta;
		else userTime.update(&key, &delta);
	}

	// Step2: 更新当前状态和时间
	us.start = time;
	us.in_user = 0;
	usermodeMap.update(&pid, &us);
}*/

// 系统调用进入的信号（同时退出用户态）
/* int trace_sys_enter() {
	u64 time = bpf_ktime_get_ns();
	struct task_struct *ts = bpf_get_current_task();
	char comm[16]; // task_struct结构体内comm的位数为16
	
	// 记录syscall次数
	u32 _key = 2;
	u64 _val = 1;
	u64 *_p = countMap.lookup(&_key);
	if (_p) *_p += 1;
	else countMap.update(&_key, &_val);

	// Step2: 记录当前syscall进入时间和状态，并更新syscMap
	struct sysc_state sysc;
	u32 pid = ts->pid;
	u64 *valp;

	sysc.start = time;
	sysc.flags = ts->flags;
	sysc.in_sysc = 1;
	sysc.pad = 0;
	syscMap.update(&pid, &sysc);
	
	on_user_exit(time, pid, ts->flags);
	return 0;
}
*/

// 系统调用退出信号
/* int trace_sys_exit() {
	u64 time = bpf_ktime_get_ns();

	on_sys_exit(time); // 使用统一的时间节点
	on_user_enter(time);
	return 0;
}
*/

// 两个CPU各自会产生一个调用，这正好方便我们使用
int tick_update(struct pt_regs *ctx) {
	if (COUNT_BPF) { // 记录插桩点执行次数
		u32 _key = 2;
		u64 _val = 1;
		u64 *_p = countMap.lookup(&_key);
		if (_p) *_p += 1;
		else countMap.update(&_key, &_val);
	}

	// bpf_trace_printk("cs_rpl = %x\n", ctx->cs & 3);
	u32 key = 0;
	u64 val, *valp;

	// 记录用户态时间，直接从头文件arch/x86/include/asm/ptrace.h中引用
	if (user_mode(ctx)) {
		u64 initval = 1;
		valp = tick_user.lookup(&key);
		if (valp) *valp += 1;
		else tick_user.update(&key, &initval);
	}

	unsigned long total_forks;
	valp = symAddr.lookup(&key);
	if (valp) {
		void *addr = (void *)(*valp);
		if (addr > 0) {
			bpf_probe_read_kernel(&total_forks, sizeof(unsigned long), addr);
			key = 1;
			val = total_forks;
			countMap.update(&key, &val);
		}
	}

	return 0;
}

/* 只有IDLE-0（0号进程）才可以执行cpu_idle的代码 */
int trace_cpu_idle(struct idleStruct *pIDLE) {
	if (COUNT_BPF) { // 记录插桩点执行次数
		u32 _key = 2;
		u64 _val = 1;
		u64 *_p = countMap.lookup(&_key);
		if (_p) *_p += 1;
		else countMap.update(&_key, &_val);
	}

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
	} else {
		// 开始idle
		u64 val = time;
		idleStart.update(&key, &val);
	}
	return 0;
}

// softirq入口函数
// SEC("tracepoint/irq/softirq_entry")
int trace_softirq_entry(struct __softirq_info *info) {
	if (COUNT_BPF) { // 记录插桩点执行次数
		u32 _key = 2;
		u64 _val = 1;
		u64 *_p = countMap.lookup(&_key);
		if (_p) *_p += 1;
		else countMap.update(&_key, &_val);
	}

	u32 key = info->vec;
	u64 val = bpf_ktime_get_ns();

	softirqCpuEnterTime.update(&key, &val);
	return 0;
}

// softirq出口函数
// SEC("tracepoint/irq/softirq_exit")
int trace_softirq_exit(struct __softirq_info *info) {
	if (COUNT_BPF) { // 记录插桩点执行次数
		u32 _key = 2;
		u64 _val = 1;
		u64 *_p = countMap.lookup(&_key);
		if (_p) *_p += 1;
		else countMap.update(&_key, &_val);
	}

	u32 key = info->vec;
	u64 now = bpf_ktime_get_ns(), *valp = 0;

	valp = softirqCpuEnterTime.lookup(&key);
	if (valp) {
		// 找到表项
		u64 last_time = now - *valp;
		u32 key0 = 0;

		valp = softirqLastTime.lookup(&key0);
		if (!valp) softirqLastTime.update(&key0, &last_time);
		else *valp += last_time;
	}
	return 0;
}

// 获取运行队列长度
// SEC("kprobe/update_rq_clock")
int update_rq_clock(struct pt_regs *ctx) {
	if (COUNT_BPF) { // 记录插桩点执行次数
		u32 _key = 2;
		u64 _val = 1;
		u64 *_p = countMap.lookup(&_key);
		if (_p) *_p += 1;
		else countMap.update(&_key, &_val);
	}

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
	if (COUNT_BPF) { // 记录插桩点执行次数
		u32 _key = 2;
		u64 _val = 1;
		u64 *_p = countMap.lookup(&_key);
		if (_p) *_p += 1;
		else countMap.update(&_key, &_val);
	}

	u32 key = info->irq;
	u64 val = bpf_ktime_get_ns();

	irqCpuEnterTime.update(&key, &val);
	return 0;
}

// SEC("tracepoint/irq/irq_handler_exit")
int trace_irq_handler_exit(struct __irq_info *info) {
	if (COUNT_BPF) { // 记录插桩点执行次数
		u32 _key = 2;
		u64 _val = 1;
		u64 *_p = countMap.lookup(&_key);
		if (_p) *_p += 1;
		else countMap.update(&_key, &_val);
	}

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