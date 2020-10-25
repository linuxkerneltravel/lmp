#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime

bpf_text = """
#include <uapi/linux/ptrace.h>

struct key_t {
    u32 cpu;
    u32 pid;
    u32 tgid;
};

BPF_HASH(start, struct key_t);
BPF_HASH(dist, struct key_t);

int pick_start(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct key_t key;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;

    start.update(&key, &ts);
    return 0;
}

int pick_end(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct key_t key;
    u64 *value;
    u64 delta;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;

    value = start.lookup(&key);

    if (value == 0) {
        return 0;
    }

    delta = ts - *value;
    start.delete(&key);
    dist.increment(key, delta);

    return 0;
}
"""


b = BPF(text=bpf_text)
b.attach_kprobe(event="pick_next_task_fair", fn_name="pick_start")
b.attach_kretprobe(event="pick_next_task_fair", fn_name="pick_end")

dist = b.get_table("dist")

print("%-6s%-6s%-6s%-6s" % ("CPU", "PID", "TGID", "TIME(ns)"))

while (1):
    try:
        sleep(1)
        for k, v in dist.items():
            print("%-6d%-6d%-6d%-6d" % (k.cpu, k.pid, k.tgid, v.value))
        dist.clear()
    except KeyboardInterrupt:
        exit()

