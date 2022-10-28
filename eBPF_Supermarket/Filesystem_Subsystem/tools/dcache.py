#!/usr/bin/python
# monitoring pagecache hit ratio
#
# Count pagecache hit ratio by specific interval
# Based on dcstat(bcc)
#
# version 2.0

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime
import re

# Print interval
interval = 1

print("Print dentry cache hit stat every %ds" % interval)

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

#define ENTER_FAST 1
#define ENTER_FAST_RCU 0

enum stats {
    S_SLOW = 1,
    S_FAST,
    S_FA_RCU,
    S_FA_REF,
    S_FA_COIN,
    S_RCU_MISS,
    S_REF_MISS,
    S_RCU_HIT,
    S_REF_HIT,
    S_MAXSTAT
};

BPF_ARRAY(counts, u64, S_MAXSTAT);
BPF_HASH(fast, u32, u8); 

int entry_lookup_slow(struct pt_regs *ctx) {
    int key = S_SLOW;
    counts.atomic_increment(key);

    return 0;
}

int entry_lookup_fast(struct pt_regs *ctx) {
    u32 pid;
    pid = bpf_get_current_pid_tgid();
    u8 flag = ENTER_FAST;
    fast.update(&pid, &flag);

    int key = S_FAST;
    counts.atomic_increment(key);

    return 0;
}

int exit_d_lookup_rcu(struct pt_regs *ctx) {
    u32 pid;
    pid = bpf_get_current_pid_tgid();
    u8 *f = fast.lookup(&pid);
    if (f != NULL && *f == ENTER_FAST) 
    {
        u8 flag = ENTER_FAST_RCU;
        fast.update(&pid, &flag);

        int key = S_FA_RCU;
        counts.atomic_increment(key); 

        if (PT_REGS_RC(ctx) == 0)
        {
            int key = S_RCU_MISS;
            counts.atomic_increment(key);
        }
        else
        {
            int key = S_RCU_HIT;
            counts.atomic_increment(key);
        }
    }

    return 0;
}

int exit_d_lookup(struct pt_regs *ctx) {
    u32 pid;
    pid = bpf_get_current_pid_tgid();
    u8 *f = fast.lookup(&pid);
    if (f != NULL && *f == ENTER_FAST) 
    {
        int key = S_FA_REF;
        counts.atomic_increment(key); 

        if (PT_REGS_RC(ctx) == 0)
        {
            int key = S_REF_MISS;
            counts.atomic_increment(key);
        }
        else
        {
            int key = S_REF_HIT;
            counts.atomic_increment(key);
        }
    }
    else if (f != NULL && *f == ENTER_FAST_RCU) 
    {
        int key = S_FA_COIN;
        counts.atomic_increment(key); 
    }

    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event_re="^lookup_fast$|^lookup_fast.constprop.*.\d$", fn_name="entry_lookup_fast")
b.attach_kprobe(event="__lookup_slow", fn_name="entry_lookup_slow")
b.attach_kretprobe(event="__d_lookup_rcu", fn_name="exit_d_lookup_rcu")
b.attach_kretprobe(event="__d_lookup", fn_name="exit_d_lookup")

# print header
stats = {
    "SLOW ": 1,
    "FAST": 2,
    "FA_RCU": 3,
    "FA_REF": 4,
    "FA_COIN": 5,
    "RCU_MISS": 6,
    "REF_MISS": 7,
    # "RCU_HIT": 8,
    # "REF_HIT": 9
}

print("%-9s  " % "TIME", end="")
for h, idx in sorted(stats.items(), key=lambda k_v: (k_v[1], k_v[0])):
    print(" %9s" % h, end="")
print(" %10s" % "RCU_HIT%", end="")
print(" %11s" % " REF_HIT%")

# output
while (1):
    try:
        sleep(interval)
    except KeyboardInterrupt:
        pass
        exit()

    print("%-9s " % strftime("%H:%M:%S"), end="")

    # print each statistic as a column
    for stype, idx in sorted(stats.items(), key=lambda k_v: (k_v[1], k_v[0])):
        try:
            val = b["counts"][c_int(idx)].value / interval
            print(" %9d" % val, end="")
        except:
            print(" %9s" % "/", end="")

    # print hit ratio percentage
    try:
        rcu = b["counts"][c_int(stats["FA_RCU"])].value
        rcu_hit = b["counts"][8].value
        rcu_pct =  float(100) * rcu_hit / rcu
        print(" %10.1f%%" % rcu_pct, end="")
    except:
        print(" %10s" % "-", end="")

    try:
        ref = b["counts"][c_int(stats["FA_REF"])].value
        ref_hit = b["counts"][9].value
        ref_pct =  float(100) * ref_hit / ref 
        print(" %10.1f%%" % ref_pct)
    except:
        print(" %10s" % "-")

    b["counts"].clear()