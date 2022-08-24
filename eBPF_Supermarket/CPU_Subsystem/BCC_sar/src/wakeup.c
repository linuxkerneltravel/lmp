#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

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

int trace_wakeup(struct wakeup_struct *ws) {
    char comm[16];
    struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(comm, 16, ts->comm);
    comm[15] = 0;

    // bpf_trace_printk("process %s-%d ", comm, ts->pid);
    // bpf_trace_printk("wakeup %s-%d.\n", ws->comm, ws->pid);
    return 0;
}

int trace_wait(struct wait_struct *ws) {
    struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
    bpf_trace_printk("pid %s-%d is waiting, current = %d\n", ws->comm, ws->pid, ts->pid);
    return 0;
}

int trace_block(struct block_struct *bs) {
    bpf_trace_printk("pid %d is blocked.\n");
    return 0;
}

int trace_sleep(struct sleep_struct *ss) {
    struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
    bpf_trace_printk("pid %s-%d is sleeping, current = %d\n", ss->comm, ss->pid, ts->pid);
    return 0;
}