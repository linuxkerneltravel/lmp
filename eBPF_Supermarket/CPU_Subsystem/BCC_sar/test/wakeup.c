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

int trace_wakeup(struct wakeup_struct *ws) {
    struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
    bpf_trace_printk("pid %d wakeup %d.\n", ts->pid, ws->pid);
    return 0;
}

int trace_wait(struct wait_struct *ws) {
    bpf_trace_printk("pid %d is waiting...\n", ws->pid);
    return 0;
}

int trace_block(struct block_struct *bs) {
    bpf_trace_printk("pid %d is blocked.\n")
    return 0;
}