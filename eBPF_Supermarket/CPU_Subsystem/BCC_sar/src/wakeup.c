#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_ARRAY(symAddr, u64, 5);

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
    // bpf_trace_printk("pid %s-%d is waiting, current = %d\n", ws->comm, ws->pid, ts->pid);
    return 0;
}

int trace_block(struct block_struct *bs) {
    bpf_trace_printk("pid %d is blocked.\n");
    return 0;
}

int trace_sleep(struct sleep_struct *ss) {
    struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
    // bpf_trace_printk("pid %s-%d is sleeping, current = %d\n", ss->comm, ss->pid, ts->pid);
    return 0;
}

// 在内核中，sizeof(long) == 8
int tick_update() {
    u32 key = 0;
    u64 *valp, v1 = 0, v2 = 0;
    valp = symAddr.lookup(&key);
    if(valp) v1 = *valp;

    key = 1;
    valp = symAddr.lookup(&key);
    if(valp) v2 = *valp;

    u64 percpu_offset[2];
    struct rq _rq;
    bpf_probe_read_kernel(percpu_offset, sizeof(u64) * 2, v1);
    u64 rq_ptr = v2 + percpu_offset[0];
    bpf_probe_read_kernel(&_rq, sizeof(struct rq), rq_ptr);

    // bpf_trace_printk("%lx %lx\n", percpu_offset[0], percpu_offset[1]);
    bpf_trace_printk("rqlen = %d\n", _rq.nr_running);
    return 0;
}