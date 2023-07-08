#include <linux/sched.h>
#define DATA_SIZE 128

typedef struct {
    u32 pid;
    int32_t sid;
} psid;

typedef struct {
    char str[TASK_COMM_LEN];
} comm;

BPF_HASH(pid_tgid, u32, u32, DATA_SIZE);
BPF_STACK_TRACE(stack_trace, DATA_SIZE);
BPF_HASH(psid_count, psid, u32, DATA_SIZE);
BPF_HASH(tgid_comm, u32, comm, DATA_SIZE);

int do_stack(void *ctx) {
    u64 _pid_tgid = bpf_get_current_pid_tgid();

    u32 pid = _pid_tgid >> 32;
    if(!pid)
        return -1;
    int32_t sid = stack_trace.get_stackid(ctx, WHICH_STACK);
    if(sid < 0)
        return -1;
    
    u32 tgid = _pid_tgid;
    pid_tgid.update(&pid, &tgid);
    psid apsid;
    apsid.pid = pid;
    apsid.sid = sid;
    psid_count.increment(apsid);

    comm *p = tgid_comm.lookup(&tgid);
    if(!p) {
        comm name;
        bpf_get_current_comm(&name, TASK_COMM_LEN);
        tgid_comm.update(&tgid, &name);
    }
    return 0;
}