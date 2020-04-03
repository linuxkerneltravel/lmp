#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <uapi/linux/ptrace.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/interrupt.h>


// Declare enough of cfs_rq to find nr_running, since we can't #import the
// header. This will need maintenance. It is from kernel/sched/sched.h:
struct cfs_rq_partial {
    struct load_weight load;
    unsigned long runnable_weight;
    unsigned int nr_running, h_nr_running;
};

//下面两个结构体保存软中断的信息
typedef struct irq_key {
    u32 vec;
    u64 slot;
} irq_key_t;

typedef struct account_val {
    u64 ts;
    u32 vec;
} account_val_t;

//这个结构体保存硬中断的信息
typedef struct hardirq_key {
    char name[32];
    u64 slot;
} hardirq_key_t;

// 自定义的数据结构，用于向用户空间传输数据
typedef struct data {
	u64 total_latency_time;		//key: 1   value： 这段时间内的总的延迟时间
	u64 total_len;				//key: 3   value： 保存运行队列长度和
	u64 total_oncpu_time;		//key: 4   value： 保存on-cpu时间
	u64 total_softirq;			//key: 5   value： 保存softirq时间
    u64 total_hardirq;          //key: 6   value： 保存hardirq时间
} data_t;

//下面两个用来保存软中断的信息
BPF_HASH(start_softirq, u32, account_val_t);
BPF_HASH(iptr, u32);

//下面两个用来保存硬中断的信息
BPF_HASH(start_hardirq, u32);
BPF_HASH(irqdesc, u32, struct irq_desc *);

//这个哈系保存BPF程序执行过程的数据，用于runqlat
BPF_HASH(start, u32);

//记录每一次的oncpu时间
BPF_HASH(start_oncpu, u32, u64);   
  

//这个哈系存储传输给用户空间的数据
//key: 1   value： 这段时间内的总的延迟时间
//key: 2   value： 间隔时间
//key: 3   value： 保存运行队列长度和
//key：4   value： 保存一个进程总的oncpu时间
//key：5   value： 保存软中断的时间
//key：6   value： 保存硬中断的时间
BPF_HASH(output, u64, u64);


BPF_PERF_OUTPUT(result);

struct rq;

// record enqueue timestamp
static int trace_enqueue(u32 tgid, u32 pid)
{
    if (0 || pid == 0)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

// 记录新创建的进程刚被调度到运行队列上的时间。
int trace_wake_up_new_task(struct pt_regs *ctx, struct task_struct *p)
{
    return trace_enqueue(p->tgid, p->pid);
}

// 记录自愿上下文切换的进程，实时进程的。
int trace_ttwu_do_wakeup(struct pt_regs *ctx, struct rq *rq, struct task_struct *p,
    int wake_flags)
{
    return trace_enqueue(p->tgid, p->pid);
}

//----------------oncpu----------------------
static inline void store_start(u32 tgid, u32 pid, u64 ts)
{
    if (tgid != 7329)
        return;

    start_oncpu.update(&pid, &ts);
}

static inline void update_hist(u32 tgid, u32 pid, u64 ts, struct pt_regs *ctx)
{
    if (tgid != 7329)
        return;
    u64 key_oncpu = 4;      //存储总的oncpu时间

    u64 *tsp = start_oncpu.lookup(&pid);
    if (tsp == 0)
        return;

    if (ts < *tsp) {
        // Probably a clock issue where the recorded on-CPU event had a
        // timestamp later than the recorded off-CPU event, or vice versa.
        return;
    }
    u64 delta = ts - *tsp;
    delta /= 1000;

    //获取当前的delta,加上这次的延迟时间
    u64 * o = output.lookup(&key_oncpu);
    if (o == 0) {
        return;
    }
    delta += *o;
    output.update(&key_oncpu,&delta);
}
//--------------------------------------------



// calculate latency
int trace(struct pt_regs *ctx, struct task_struct *prev)
{
    u32 pid, tgid;

    //output哈系的key值定义用于回传给用户空间
    u64 key_latency_time = 1;		//存储总的延迟时间
    u64 key_time = 2;		//存储时间（1s）
    u64 key_len = 3;		//存储排队进程总数
    u64 key_oncpu = 4;      //存储总的oncpu时间
    u64 key_total_softirq = 5;  //存储总的softirq时间
    u64 key_total_hardirq = 6;  //存储总的hardirq时间


	u64 zero = 0;	//用于数据清零

	//-------oncpu-----------------
	u64 tss = bpf_ktime_get_ns();
    tgid = bpf_get_current_pid_tgid() >> 32;
    pid = bpf_get_current_pid_tgid();

    if (prev->state == TASK_RUNNING) {
        u32 prev_pid = prev->pid;
        u32 prev_tgid = prev->tgid;
        update_hist(prev_tgid, prev_pid, tss, ctx);
    }
    u64 * oc = output.lookup_or_init(&key_oncpu,&zero);
    if (oc == 0) {
        return 0;
    }
    //-----------------------------

    // ivcsw: treat like an enqueue event and store timestamp
    // 记录非自愿上下文切换的时间
    if (prev->state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (!(pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }

    tgid = bpf_get_current_pid_tgid() >> 32;
    pid = bpf_get_current_pid_tgid();

    if (pid == 0)
        return 0;


    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    // 计算当前这个进程和上一次调度的时间差
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000;
//------------------------------------------------

	//获取当前的delta,加上这次的延迟时间
    u64 * o = output.lookup_or_init(&key_latency_time,&delta);
    if (o == NULL) {
    	return 0;
    }
    u64 now_delta = *o + delta;
    output.update(&key_latency_time,&now_delta);

    // //初始化key_total_softirq
    // u64 * kts = output.lookup_or_init(&key_total_softirq,&zero);
    // if (kts == NULL) {
    //     return 0;
    // }


    //获取上一次的时间
    u64 cur = bpf_ktime_get_ns();
	u64 * time_old = output.lookup_or_init(&key_time,&cur);
	if (time_old == NULL) {
		return 0;
	}

	//1秒时间到
	if (cur-*time_old >= 1000000000) {
		data_t data = {};
		//先更新时间
		output.update(&key_time,&cur);
    	//传送给用户空间
    	u64 *lt = output.lookup(&key_latency_time);
    	if (lt == NULL) {
    		return 0;
    	}
    	data.total_latency_time = *lt;

    	//传送给用户空间
    	u64 *l = output.lookup(&key_len);
    	if (l == NULL) {
    		return 0;
    	}
		data.total_len = *l;

		//传送给用户空间
		u64 * o = output.lookup(&key_oncpu);
        if (o == NULL) {
            return 0;
        }
        data.total_oncpu_time = *o;
        //传送给用户空间
		u64 * kts = output.lookup(&key_total_softirq);
        if (kts == NULL) {
            return 0;
        }
        data.total_softirq = *kts / 1000;
        //传送给用户空间
        u64 * kth = output.lookup(&key_total_hardirq);
        if (kth == NULL) {
            return 0;
        }
        data.total_hardirq = *kth / 1000;
                
    	result.perf_submit(ctx, &data, sizeof(data));
    	//把已经提取的数据清零
    	output.update(&key_latency_time,&zero);
    	output.update(&key_len,&zero);
    	output.update(&key_oncpu,&zero);
    	output.update(&key_total_softirq,&zero);
        output.update(&key_total_hardirq,&zero);
        
	}

BAIL:
    store_start(tgid, pid, tss);

    return 0;
}


//用于统计调度队列长度
int do_perf_event(struct pt_regs *ctx)
{
	//用于回传给用户空间
    u64 key_len = 3;		//存储排队进程总数

    u64 len = 0;
    pid_t pid = 0;
    struct task_struct *task = NULL;
    struct cfs_rq_partial *my_q = NULL;

    // Fetch the run queue length from task->se.cfs_rq->nr_running. This is an
    // unstable interface and may need maintenance. Perhaps a future version
    // of BPF will support task_rq(p) or something similar as a more reliable
    // interface.
    task = (struct task_struct *)bpf_get_current_task();
    my_q = (struct cfs_rq_partial *)task->se.cfs_rq;
    len = my_q->nr_running;

    // Calculate run queue length by subtracting the currently running task,
    // if present. len 0 == idle, len 1 == one running task.
    if (len > 0)
        len--;
    //在这里进行长度的累加。
    u64 * o = output.lookup_or_init(&key_len,&len);
    if (o == NULL) {
    	return 0;
    }
    u64 now_len = *o + len;
    output.update(&key_len,&now_len);

    return 0;
}




//下面两个函数是软中断的函数
TRACEPOINT_PROBE(irq, softirq_entry)
{
    u64 key_total_softirq = 5;
    u64 zero = 0;

    u32 pid = bpf_get_current_pid_tgid();
    account_val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.vec = args->vec;
    start_softirq.update(&pid, &val);
    // u64 * o = output.lookup_or_init(&key_total_softirq,&zero);
    // if (o == NULL) {
    //     return 0;
    // }
    return 0;
}



TRACEPOINT_PROBE(irq, softirq_exit)
{
    u64 key_total_softirq = 5;
    u64 zero = 0;
    u64 delta;
    u32 vec;
    u32 pid = bpf_get_current_pid_tgid();
    account_val_t *valp;
    irq_key_t key = {0};

    // fetch timestamp and calculate delta
    valp = start_softirq.lookup(&pid);
    if (valp == 0) {
        return 0;   
    }
    delta = bpf_ktime_get_ns() - valp->ts;
    vec = valp->vec;

    // store as sum or histogram
    key.vec = valp->vec; //dist.increment(key, delta);

    //把所有的值加到一起，
    u64 * kts = output.lookup_or_init(&key_total_softirq,&zero);
    if (kts == NULL) {
        return 0;
    }
    delta += *kts;
    output.update(&key_total_softirq, &delta);

    start_softirq.delete(&pid);
    return 0;
}


//下面两个函数是硬中断的函数
// time IRQ
int trace_start(struct pt_regs *ctx, struct irq_desc *desc)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_hardirq.update(&pid, &ts);
    irqdesc.update(&pid, &desc);
    return 0;
}

int trace_completion(struct pt_regs *ctx)
{
    u64 key_total_hardirq = 6;
    u64 zero = 0;
    u64 *tsp, delta;
    struct irq_desc **descp;
    u32 pid = bpf_get_current_pid_tgid();

    // fetch timestamp and calculate delta
    tsp = start_hardirq.lookup(&pid);
    descp = irqdesc.lookup(&pid);
    if (tsp == 0 || descp == 0) {
        return 0;   // missed start
    }
    struct irq_desc *desc = *descp;
    struct irqaction *action = desc->action;
    char *name = (char *)action->name;
    delta = bpf_ktime_get_ns() - *tsp;

    // store as sum or histogram
    hardirq_key_t key = {.slot = 0 /* ignore */};
    bpf_probe_read(&key.name, sizeof(key.name), name);
    //dist.increment(key, delta);

    //把所有的值加到一起，
    u64 * kts = output.lookup_or_init(&key_total_hardirq,&zero);
    if (kts == NULL) {
        return 0;
    }
    delta += *kts;
    output.update(&key_total_hardirq, &delta);
    start_hardirq.delete(&pid);
    irqdesc.delete(&pid);
    return 0;
}












