#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Declare enough of cfs_rq to find nr_running, since we can't #import the
// header. This will need maintenance. It is from kernel/sched/sched.h:
struct cfs_rq_partial {
    struct load_weight load;
    unsigned long runnable_weight;
    unsigned int nr_running, h_nr_running;
};

struct data_t {
    unsigned int len;
};


//存储数据
BPF_PERF_OUTPUT(result);

int do_perf_event(struct pt_regs *ctx)
{
    unsigned int len = 0;
    struct data_t data = {};
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
    // 减去当前正在运行的任务
    // if present. len 0 == idle, len 1 == one running task.
    if (len > 0)
        len--;

    data.len = len;

    //给直方图中传入数据
    //dist.increment(len);
    result.perf_submit(ctx, &data, sizeof(data));


    return 0;
}