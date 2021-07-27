#include <uapi/linux/ptrace.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/interrupt.h>

struct key_t {
    u32 cpu;
    u32 pid;
    u32 tgid;
};

BPF_HASH(enter, struct key_t);
BPF_HASH(exitt, struct key_t);

int handler_start(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct key_t key;

    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;
    key.cpu = bpf_get_smp_processor_id();

    enter.update(&key, &ts);
    return 0;
}

int handler_end(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *value;
    u64 delta;
    struct key_t key;

    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;
    key.cpu = bpf_get_smp_processor_id();

    value = enter.lookup(&key);

    if (value == 0) {
        return 0;
    }

    delta = ts - *value;
    enter. delete(&key);
    exitt.increment(key, delta);
    return 0;
}
