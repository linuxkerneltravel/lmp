from __future__ import print_function
from bcc import BPF
from time import sleep
import argparse

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cpuidle.h>

typedef struct cpuidle_key {
    u32     cpu;
    u64     exit_latency_ns;
} cpuidle_key_t;

typedef struct cpuidle_info {
    u32     cpu;
    char    name[CPUIDLE_NAME_LEN];
    u64     exit_latency_ns;
    u64     target_residency_ns;
    u64     start;
    u64     total;
    u32     less;
    u32     more;
} cpuidle_info_t;

BPF_HASH(idle_start, u32, cpuidle_key_t);
BPF_HASH(idle_account, cpuidle_key_t, cpuidle_info_t);

// kernel_function : sched_idle_set_state
int do_idle_start(struct pt_regs *ctx, struct cpuidle_state *target_state) {
    cpuidle_key_t key = {}, *key_p;
    cpuidle_info_t info = {}, *info_p;

    u32 cpu = bpf_get_smp_processor_id();
    u64 delta, ts = bpf_ktime_get_ns();

    if (target_state == NULL) {

        key_p = idle_start.lookup(&cpu);
        if (key_p == 0) {
            return 0;
        }

        key.cpu = key_p->cpu;
        key.exit_latency_ns = key_p->exit_latency_ns;

        info_p = idle_account.lookup(&key);
        if (info_p) {
            delta = ts - info_p->start;

            info_p->total += delta;

            if (delta > (info_p->exit_latency_ns + info_p->target_residency_ns))
                info_p->more++;
            else
                info_p->less++;
        }

        return 0;

    };

    key.cpu = cpu;
    key.exit_latency_ns = target_state->exit_latency_ns;

    idle_start.update(&cpu, &key);

    info_p = idle_account.lookup(&key);
    if (info_p) {
        info_p->start = ts;
    } else {
        info.cpu = cpu;
        bpf_probe_read_kernel(&(info.name), sizeof(info.name), target_state->name);

        info.exit_latency_ns = target_state->exit_latency_ns;
        info.target_residency_ns = target_state->target_residency_ns;

        info.start = ts;
        info.total = 0;
        info.less = info.more = 0;

        idle_account.update(&key, &info);
    }

    return 0;
}

"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="sched_idle_set_state", fn_name="do_idle_start")

idle_account = b.get_table("idle_account")

while (1):
    sleep(1)

    for k, v in idle_account.items():
            print("%3d %16s %9d %9d %13d %9d %9d" % (v.cpu, v.name, v.exit_latency_ns, v.target_residency_ns, v.total, v.less, v.more))
    
    print("======")

    idle_account.clear()
    

