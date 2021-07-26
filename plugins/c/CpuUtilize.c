#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 cpu;
    u32 pid;
    u32 tgid;
};

struct time_t {
    u64 total;
    u64 idle;
};

BPF_HASH(start, struct key_t);
BPF_HASH(dist, u32, struct time_t);

int pick_start(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct key_t key;
    struct time_t cpu_time, *time_prev;
    u32 cpu, pid;
    u64 *value, delta;

    cpu = key.cpu = bpf_get_smp_processor_id();
    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;

    start.update(&key, &ts);

    pid = key.pid = prev->pid;
    key.tgid = prev->tgid;

    value = start.lookup(&key);

    if (value == 0) {
        return 0;
    }

    delta = ts - *value;
    start.delete(&key);

    time_prev = dist.lookup(&cpu);

    if (time_prev == 0) {
        cpu_time.total = 0;
        cpu_time.idle = 0;
    }else {
        cpu_time = *time_prev;
    }

    cpu_time.total += delta;

    if (pid == 0) {
        cpu_time.idle += delta;
    }

    dist.update(&cpu, &cpu_time);

    return 0;
}