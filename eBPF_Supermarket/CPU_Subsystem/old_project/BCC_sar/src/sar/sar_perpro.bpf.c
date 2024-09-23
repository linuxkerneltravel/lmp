#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#define TARGET_PID 2069

typedef int pid_t;
BPF_ARRAY(TotalMap, u64, 9);

#define schedCount 0
#define startTime 1
#define threadLastTime 2
#define userTime 3
#define softirqEnterTime 4
#define softirqLastTime 5
#define irqEnterTime 6
#define irqLastTime 7
#define syscTime 8

struct sysc_state {
	u64 start;
	u64 in_sysc;
};
BPF_ARRAY(syscMap, struct sysc_state, 1);

struct user_state {
	u64 start;
	u64 in_user;
};

BPF_HASH(usermodeMap, u32, struct user_state, 1024);

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

__always_inline static void on_user_enter(u64 time) {
	u32 key = 0;
	struct user_state us;

	us.start = time;
	us.in_user = 1;

	// Step2: 更新usermodeMap
	usermodeMap.update(&key, &us);
}

// 在sched_switch中记录系统调用花费的时间
__always_inline static void record_sysc(u64 time, pid_t prev, pid_t next) {
	// 分别处理旧进程和新的进程
	// 旧进程：检查是否处于系统调用中，如果是，就将累积的时间加到syscTime
	u32 key = 0;
	struct sysc_state* stat;
	if (prev == TARGET_PID) {
		stat = syscMap.lookup(&key);
		if (stat && stat->in_sysc) {
			u64 delta = time - stat->start;

			key = syscTime;
			u64 *valq = TotalMap.lookup(&key);
			if (valq) *valq += delta;
			else TotalMap.update(&key, &delta);
		}
	}

	// 新进程：检查是否处于系统调用中，如果是，就将其开始时间更新为当前
	key = 0;
	stat = syscMap.lookup(&key);
	if (stat && stat->in_sysc) {
		stat->start = time;
	}
}

__always_inline static void record_user(u64 time, pid_t prev, pid_t next) {
	// 旧进程：检查是否处于用户态，如果是，更新总时间userTime
	u32 key = 0;
	struct user_state *us;
	if (prev == TARGET_PID) {
		us = usermodeMap.lookup(&key);
		if (us && us->in_user) {
			u64 delta = time - us->start;

			key = userTime;
			u64 *valp = TotalMap.lookup(&key);
			if (valp) *valp += delta;
			else TotalMap.update(&key, &delta);
		}
	}

	// 新进程：检查是否处于用户态，如果是，更新起始时间
	key = 0;
	if (next == TARGET_PID) {
		us = usermodeMap.lookup(&key);
		if (us && us->in_user) {
			us->start = time;
		}
	}
}

__always_inline static void on_sys_exit(u64 time) {
	// Step2：累加进程Syscall时间到syscTime
	struct sysc_state sysc;
	u32 key = 0;
	u64 delta;
	struct sysc_state *valp;
	
	valp = syscMap.lookup(&key);

	// Step2.5 确保当前进程之前存在记录，且处于sysc状态
	if (valp && valp->in_sysc) {
		delta = time - valp->start;
		key = syscTime;

		u64 *valq = TotalMap.lookup(&key);
		if (valq) *valq += delta;
		else TotalMap.update(&key, &delta);
	}

	// Step3: 更新进程的Syscall状态为不在Syscall，并更新进入时间（Optional）
	key = 0;
	sysc.start = time;
	sysc.in_sysc = 0;
	syscMap.update(&key, &sysc);
}

// 进入用户态
// int exit_to_user_mode_prepare() {
// 	// Step1: 记录user开始时间，和当前的in_user状态
// 	struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
// 	if (ts->pid != TARGET_PID) return 0;
// 	u64 time = bpf_ktime_get_ns();

// 	on_user_enter(time);
// 	on_sys_exit(time);

// 	return 0;
// }

// 获取进程切换数
int trace_sched_switch(struct cswch_args *info) {
	pid_t prev = info->prev_pid, next = info->next_pid;

	if (prev != next && (prev == TARGET_PID || next == TARGET_PID)) {
		u32 key = 0;
		u64 *valp, initval = 1;
		u64 time = bpf_ktime_get_ns();

		// 1. 更新上下文切换次数
		if (next == TARGET_PID) {
			key = schedCount;
			valp = TotalMap.lookup(&key);
			if (valp) *valp += 1;
			else TotalMap.update(&key, &initval);

			// 2. 记录开始时间
			key = startTime;
			TotalMap.update(&key, &time);
		}
		
		// 3. 记录进程此次执行的时间
		if (prev == TARGET_PID) {
			key = startTime;
			valp = TotalMap.lookup(&key);
			u64 delta = 0;
			if (valp) delta = time - *valp;

			key = threadLastTime;
			valp = TotalMap.lookup(&key);
			if (valp) *valp += delta;
			else TotalMap.update(&key, &delta);
		}

		// Step2: Syscall时间处理
		record_sysc(time, prev, next);

		// Step3: UserMode时间处理
		record_user(time, prev, next);
	}

	return 0;
}

__always_inline static void on_user_exit(u64 time) {
	// Step1: 查询之前进入用户态的时间，记录退出用户态的时间，并将其累加到userTime
	struct user_state *valp, us;
	u32 key = 0;

	valp = usermodeMap.lookup(&key);
	if (valp && valp->in_user) {
		u64 delta = time - valp->start;

		key = userTime;
		u64 *valq = TotalMap.lookup(&key);
		if (valq) *valq += delta;
		else TotalMap.update(&key, &delta);
	}

	// Step2: 更新当前状态和时间
	us.start = time;
	us.in_user = 0;
	key = 0;
	usermodeMap.update(&key, &us);
}

// 系统调用进入的信号（同时退出用户态）
int trace_sys_enter() {
	char comm[16]; // task_struct结构体内comm的位数为16
	struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
	if (ts->pid != TARGET_PID) return 0;

	// Step2: 记录当前syscall进入时间和状态，并更新syscMap
	struct sysc_state sysc;
	u32 key = 0;
	u64 *valp, time = bpf_ktime_get_ns();

	sysc.start = time;
	sysc.in_sysc = 1;
	syscMap.update(&key, &sysc);
	
	on_user_exit(time);
	return 0;
}

// // 系统调用退出信号
// int trace_sys_exit() {
// 	struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
// 	if (ts->pid != TARGET_PID) return 0;

// 	return 0;
// }

// softirq入口函数
// SEC("tracepoint/irq/softirq_entry")
int trace_softirq_entry(struct __softirq_info *info) {
	struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
	if (ts->pid != TARGET_PID) return 0;

	u32 key = softirqEnterTime;
	u64 val = bpf_ktime_get_ns();

	TotalMap.update(&key, &val);
	return 0;
}

// softirq出口函数
// SEC("tracepoint/irq/softirq_exit")
int trace_softirq_exit(struct __softirq_info *info) {
	struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
	if (ts->pid != TARGET_PID) return 0;

	u32 key = softirqEnterTime;
	u64 now = bpf_ktime_get_ns(), *valp = 0;

	valp = TotalMap.lookup(&key);
	if (valp) {
		// 找到表项
		u64 delta = now - *valp;
		key = softirqLastTime;

		valp = TotalMap.lookup(&key);
		if (!valp) TotalMap.update(&key, &delta);
		else *valp += delta;
	}
	return 0;
}

// SEC("tracepoint/irq/irq_handler_entry")
int trace_irq_handler_entry(struct __irq_info *info) {
	struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
	if (ts->pid != TARGET_PID) return 0;

	u32 key = irqEnterTime;
	u64 val = bpf_ktime_get_ns();

	TotalMap.update(&key, &val);
	return 0;
}

// SEC("tracepoint/irq/irq_handler_exit")
int trace_irq_handler_exit(struct __irq_info *info) {
	struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
	if (ts->pid != TARGET_PID) return 0;

	u32 key = irqEnterTime;
	u64 now = bpf_ktime_get_ns(), *valp = 0;

	valp = TotalMap.lookup(&key);
	if (valp) {
		// 找到表项
		u64 delta = now - *valp;
		key = irqLastTime;
		valp = TotalMap.lookup(&key);

		if (!valp) {
			TotalMap.update(&key, &delta);
		} else {
			*valp += delta;
		}
	}
	return 0;
}