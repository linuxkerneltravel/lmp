#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define PRINT_SLEEP 1
#define TARGET_PID 10327

BPF_ARRAY(symAddr, u64, 5);
BPF_ARRAY(countMap, u64, 1);
BPF_ARRAY(ownPid, int, 1);
BPF_STACK_TRACE(stacktraces, 50009);

struct sleep_record {
    u32 state;
    u32 in_sleep;
    u64 start;
};

BPF_HASH(sleepBegin, int, struct sleep_record, 4096);
BPF_HASH(sleeplast, int, u64, 4096);
BPF_HASH(runlast, int, u64, 4096);
BPF_HASH(runBegin, int, u64, 4096);
BPF_HASH(waitlast, int, u64, 4096);
BPF_HASH(waitBegin, int, u64, 4096);

BPF_PERF_OUTPUT(events);

struct wakeup_struct {
    unsigned long long pad;
    char comm[16];
    int pid;
    int prio;
    int success;
    int target_cpu;
};

struct wait_struct {
    unsigned long long pad;
    char comm[16];
    int pid;
    int prio;
};

struct sleep_struct {
    unsigned long long pad;
    char comm[16];
    int pid;
    u64 delay;
};

struct rq {
	raw_spinlock_t lock;
	unsigned int nr_running;
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
	unsigned int numa_migrate_on;
	long unsigned int last_blocked_load_update_tick;
	unsigned int has_blocked_load;
};


struct cswch_args {
	unsigned long long pad;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
};

#define TASK_RUNNING			0x0000
#define TASK_INTERRUPTIBLE		0x0001
#define TASK_UNINTERRUPTIBLE		0x0002


#define BEGIN_SLEEP 1
#define END_SLEEP 2
#define BEGIN_WAIT 3
#define END_WAIT 4
#define BEGIN_RUN 5
#define END_RUN 6

struct perf_data {
    int stackid; // 调用栈的信息: waker/sleeper
    int pid;
    char comm[16];
    int type;
    int waker;
    char waker_comm[16];
    u64 time;
    int preempt_count;
};

__always_inline static void inc_count() {
    u32 key = 0;
    u64 initval = 1, *valp = countMap.lookup(&key);
    if (valp) *valp += 1;
    else countMap.update(&key, &initval);
}

__always_inline static int getMyPid() {
    u32 key = 0;
    int *valp = ownPid.lookup(&key);
    if (valp) return *valp;
    else return -1;
}

__always_inline static void copy_comm(char *src, char *dst) {
    for (int i = 0; i < 15; i++) {
        dst[i] = src[i];
    }
    dst[15] = 0;
}

// 获取当前运行的cpu上抢占标志位的值
__always_inline static int get_preempt_count() {
    u64 *valp;
    u64 p_offset = 0, p_preempt = 0;

    u32 key = 0;
    valp = symAddr.lookup(&key);
    if(valp) p_offset = *valp;

    key = 2;
    valp = symAddr.lookup(&key);
    if(valp) p_preempt = *valp;

    u64 percpu_offset[2];
    bpf_probe_read_kernel(percpu_offset, sizeof(u64) * 2, p_offset);

    int preempt_count = 125868; // magic number 125868表示出错
    // 变量值在BPF中做下标时，需要限制范围
    u32 cpu = bpf_get_smp_processor_id();
    // bpf_trace_printk("cpu = %d\n", cpu);

    // May Be BPF's Problem? So I have to get percpu_offset in this stupid way.
    // tmp记录了percpu_offset(u64)的某个值，坚决不能用int或者u32，因为向下转型会出现问题！！
    u64 tmp;
    if (cpu == 1) {
        tmp = percpu_offset[1];
    }
    else {
        tmp = percpu_offset[0];
    }

    // p_preempt = p_preempt + tmp;
    bpf_probe_read_kernel(&preempt_count, sizeof(preempt_count), p_preempt + tmp);
    preempt_count = preempt_count & (0x7fffffff);
    return preempt_count;
}

// 事件统一用perf output形式传递到用户空间

// from trace_sched_switch
__always_inline static void begin_sleep(struct pt_regs *ctx) {
    struct task_struct *ts = bpf_get_current_task();
    u32 pid = ts->pid;
    struct perf_data data = {};

    data.stackid = stacktraces.get_stackid(ctx, 0);
    data.pid = pid;
    data.type = BEGIN_SLEEP;
    data.waker = 0;
    // u64 bpf_ktime_get_ns(void) Description Return the time elapsed since system boot, in nanoseconds.
    data.time = bpf_ktime_get_ns();
    data.preempt_count = 0;

    // 获取进程的comm
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 向用户空间传送睡眠进程名、pid以及发生阻塞时的栈信息
    events.perf_submit(ctx, &data, sizeof(data));
    // inc_count();
    // bpf_trace_printk("#%-8d Begin Sleep", pid);
}

// #<pid>表示主语为pid
__always_inline static void end_sleep(struct pt_regs *waker_ctx, 
                                      struct wakeup_struct *ws, int waker_pid) {
    struct perf_data data = {};
    struct task_struct *ts = bpf_get_current_task();

    data.stackid = stacktraces.get_stackid(waker_ctx, 0);
    data.pid = ws->pid;
    data.type = END_SLEEP;
    data.waker = waker_pid;
    bpf_probe_read_kernel(data.waker_comm, 16, ts->comm);
    data.comm[15] = 0;
    copy_comm(ws->comm, data.comm);
    data.time = bpf_ktime_get_ns();
    data.preempt_count = get_preempt_count();

    events.perf_submit(waker_ctx, &data, sizeof(data));
    // bpf_trace_printk("#%-8d Wakeup %d", waker_pid, ws->pid);
    // bpf_trace_printk("#%-8d End Sleep", ws->pid);
    // inc_count();
}

__always_inline static void begin_run(int pid, char *comm, struct pt_regs *ctx) {
    struct perf_data data = {};

    data.stackid = 0;
    data.pid = pid;
    data.type = BEGIN_RUN;
    data.waker = 0;
    copy_comm(comm, data.comm);
    data.time = bpf_ktime_get_ns();
    data.preempt_count = 0;

    events.perf_submit(ctx, &data, sizeof(data));
    // bpf_trace_printk("#%-8d Begin Run", pid);
    // inc_count();
}

__always_inline static void end_run(int pid, char *comm, struct pt_regs *ctx) {
    struct perf_data data = {};

    data.stackid = 0;
    data.pid = pid;
    data.type = END_RUN;
    data.waker = 0;
    copy_comm(comm, data.comm);
    data.time = bpf_ktime_get_ns();
    data.preempt_count = 0;

    events.perf_submit(ctx, &data, sizeof(data));
    // bpf_trace_printk("#%-8d End Run", pid);
    // inc_count();
}

__always_inline static void begin_wait(int pid, char *comm, struct pt_regs *ctx) {
    struct perf_data data = {};

    data.stackid = 0;
    data.pid = pid;
    data.type = BEGIN_WAIT;
    data.waker = 0;
    copy_comm(comm, data.comm);
    data.time = bpf_ktime_get_ns();
    data.preempt_count = 0;

    events.perf_submit(ctx, &data, sizeof(data));
    // bpf_trace_printk("#%-8d Begin Wait", pid);
    // inc_count();
}

__always_inline static void end_wait(int pid, char *comm, struct pt_regs *ctx) {
    struct perf_data data = {};

    data.stackid = 0;
    data.pid = pid;
    data.type = END_WAIT;
    data.waker = 0;
    copy_comm(comm, data.comm);
    data.time = bpf_ktime_get_ns();
    data.preempt_count = 0;

    events.perf_submit(ctx, &data, sizeof(data));
    // bpf_trace_printk("#%-8d End Wait", pid);
    // inc_count();
}

int trace_sched_switch(struct cswch_args *ctx) {
    int myPid = getMyPid();
    inc_count();
    if (ctx->next_pid == ctx->prev_pid) return 0;
    // if (ctx->next_pid == myPid || ctx->prev_pid == myPid) return 0;

    struct task_struct *ts = bpf_get_current_task();
    struct sleep_record sr;
    u32 next = ctx->next_pid, prev = ctx->prev_pid;
    u64 time = bpf_ktime_get_ns(), *valp, delta, initval = 0;

    begin_run(ctx->next_pid, ctx->next_comm, ctx);
    end_run(ctx->prev_pid, ctx->prev_comm, ctx);

    // state 在新版的linux内核中被改成了_state
    if ( (ts->__state & TASK_INTERRUPTIBLE) || (ts->__state & TASK_UNINTERRUPTIBLE) ) {
        // 进入睡眠状态
        sr.state = ts->__state;
        sr.in_sleep = 1;
        sr.start = time;
        sleepBegin.update(&prev, &sr);

        begin_sleep((struct pt_regs *)ctx);
    } else if (ts->__state == TASK_RUNNING) {
        // 开始等待
        waitBegin.update(&prev, &time);
        begin_wait(ctx->prev_pid, ctx->prev_comm, ctx);
    }

    // 更新新进程的开始执行时间
    runBegin.update(&next, &time);

    // // next: 结束睡眠(一般不可能。一般要先被wakeup，不可能直接被调度运行)
    // struct sleep_record *p_sr;
    // p_sr = sleepBegin.lookup(&next);
    // if (p_sr && p_sr->in_sleep) {
    //     u64 last = time - p_sr->start;
    //     bpf_trace_printk("end sleep %d us\n", last);
    // }

    // next: 结束等待
    end_wait(ctx->next_pid, ctx->next_comm, ctx);
    valp = waitBegin.lookup(&next);
    if (valp && *valp != 0) {
        // bpf_trace_printk("valp = %llu\n", *valp);
        delta = time - *valp;

        valp = waitlast.lookup(&next);
        if (valp) *valp += delta;
        else waitlast.update(&next, &delta);

        waitBegin.update(&next, &initval);
    }

    // 统计旧进程的执行时间
    valp = runBegin.lookup(&prev);
    if (valp) {
        delta = time - *valp;
        valp = runlast.lookup(&prev);
        if (valp) *valp += delta;
        else runlast.update(&prev, &delta);
    }
    
    return 0;
}


int trace_wakeup(struct wakeup_struct *ws) {
    inc_count();
    struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
    int myPid = getMyPid();
    // if (ws->pid == myPid && ts->pid == myPid) return 0;

    // char comm[16];
    // bpf_probe_read_kernel(comm, 16, ts->comm);
    // comm[15] = 0;

    bpf_trace_printk("wakeup_preempt = %d\n", get_preempt_count());

    u32 pid = ws->pid;
    u64 *valp, nowtime = bpf_ktime_get_ns();
    struct sleep_record *p_sr = sleepBegin.lookup(&pid);
    if (p_sr && p_sr->in_sleep) {
        u64 time = nowtime - p_sr->start;
        // if (time > 1000000 && PRINT_SLEEP && pid == TARGET_PID) { // 1ms
        //     bpf_trace_printk("process %d sleep for %d us.(wakeup by %d)\n", pid, time / 1000, ts->pid);
        // }
        p_sr->in_sleep = 0;

        // 结束睡眠
        end_sleep((struct pt_regs *)ws, ws, ts->pid);

        // 开始等待
        waitBegin.update(&pid, &nowtime);
        begin_wait(pid, ws->comm, ws);

        valp = sleeplast.lookup(&pid);
        if (valp) *valp += time;
        else sleeplast.update(&pid, &time);
    }
    
    return 0;
}

// 在内核中，64位系统的 sizeof(long) == 8
int tick_update() {
    u64 *valp;
    u64 p_offset = 0, p_rq = 0;

    u32 key = 0;
    valp = symAddr.lookup(&key);
    if(valp) p_offset = *valp;

    key = 1;
    valp = symAddr.lookup(&key);
    if(valp) p_rq = *valp;

    u64 percpu_offset[2];
    struct rq _rq;
    bpf_probe_read_kernel(percpu_offset, sizeof(u64) * 2, p_offset);
    u64 rq_ptr = p_rq + percpu_offset[0]; // 默认读取CPU0的Rq
    bpf_probe_read_kernel(&_rq, sizeof(struct rq), rq_ptr);
    
    // int preempt_count = get_preempt_count();
    // bpf_trace_printk("preempt_count = %d\n", preempt_count);
    
    struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
    int *pusage = &ts->usage; // usage表示进程被等待队列引用的数目
    // bpf_trace_printk("curr task usage = %d\n", *pusage);

    // 读取rq
    // bpf_trace_printk("%lx %lx\n", percpu_offset[0], percpu_offset[1]);
    // bpf_trace_printk("rqlen = %d\n", _rq.nr_running);
    return 0;
}


// 主要想评估一下是否wakeup成功，但是我觉得在trace_wake里面wake的程序应该都能成功
int kprobe_try_to_wake_up(struct pt_regs *ctx) {
    struct task_struct *p = PT_REGS_PARM1(ctx);
    struct task_struct *curr = bpf_get_current_task();
    bpf_trace_printk("try_to_wake_up %d, which state = %x", p->pid, p->__state);

    return 0;
}

// 获取返回值例程
int kretprobe_try_to_wake_up(struct pt_regs *ctx) {
    // 从ctx里读取返回值
    int ret = PT_REGS_RC(ctx);

    bpf_trace_printk("[%d]try_to_wake_up", ret);
    return 0;
}