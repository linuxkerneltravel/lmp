#include <linux/sched.h>

typedef struct {
    u32 pid;
    int32_t ksid, usid;
} psid;

typedef struct {
    char str[TASK_COMM_LEN];
} comm;

BPF_HASH(pid_tgid, u32, u32);
BPF_STACK_TRACE(stack_trace, STACK_STORAGE_SIZE);
BPF_HASH(psid_count, psid, u32);
BPF_HASH(pid_comm, u32, comm);

int do_stack(void *ctx) {
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    if(!((THREAD_FILTER) && (STATE_FILTER)))
        return -1;
    
    u32 pid = curr->pid;
    u32 tgid = curr->tgid;
    pid_tgid.update(&pid, &tgid);
    comm *p = pid_comm.lookup(&pid);
    if(!p) {
        comm name;
        bpf_probe_read_kernel_str(&name, TASK_COMM_LEN, curr->comm);
        pid_comm.update(&pid, &name);
    }
    psid apsid = {
        .pid = pid,
        .ksid = KERNEL_STACK_GET,
        .usid = USER_STACK_GET,
    };
    psid_count.increment(apsid);
    return 0;
}