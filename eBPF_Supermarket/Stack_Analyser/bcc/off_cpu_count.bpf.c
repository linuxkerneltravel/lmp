#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MINBLOCK_US    1ULL
#define MAXBLOCK_US    99999999ULL

typedef struct {
    u32 pid;
    int usid;
    int ksid;
} psid;

typedef struct {
    char str[TASK_COMM_LEN];
} comm;

BPF_HASH(psid_count, psid);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_trace, STACK_STORAGE_SIZE);
BPF_HASH(pid_tgid, u32, u32);
BPF_HASH(pid_comm, u32, comm);

int do_stack(struct pt_regs *ctx, struct task_struct *curr) {
    u32 pid = curr->pid;
    u32 tgid = curr->tgid;

    if ((THREAD_FILTER) && (STATE_FILTER)) {
        u64 ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }

    struct task_struct *next = (struct task_struct *)bpf_get_current_task();
    pid = next->pid;
    u64 *tsp = start.lookup(&pid);
    if (tsp == 0) return 0;

    start.delete(&pid);
    u64 delta = bpf_ktime_get_ns() - *tsp;
    delta /= 10000000;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US)) {
        return 0;
    }
    
    tgid = next->tgid;
    pid_tgid.update(&pid, &tgid);
    comm *p = pid_comm.lookup(&pid);
    if(!p) {
        comm name;
        bpf_probe_read_kernel_str(&name, TASK_COMM_LEN, next->comm);
        pid_comm.update(&pid, &name);
    }
    psid key = {
        .pid = pid,
        .usid = USER_STACK_GET,
        .ksid = KERNEL_STACK_GET,
    };
    psid_count.increment(key, delta);

    return 0;
}