#!/usr/bin/python
# monitoring vfs_function
#
# Count VFS method by specific interval and sorted by counts
# Based on vfscount(bcc)
#
# version 1.0

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime
#import os

# Debug C prog
debug = 0

# Print interval
interval = 2

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

struct key_t {
    u64 ip;
};

BPF_HASH(counts, struct key_t, u64, 256);

static void counts_increment(struct key_t key) {
    counts.atomic_increment(key);
}
"""

bpf_text_kprobe = """
int do_count(struct pt_regs *ctx) {
    struct key_t key = {};
    key.ip = PT_REGS_IP(ctx);   
    //PT_REGS_IP:return kernel IP

    //counts.atomic_increment(key);
    counts_increment(key);
    return 0;
}
"""

bpf_text += bpf_text_kprobe

# Pint debug info
if debug:
    print(bpf_text)

# Initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event_re="^vfs_.*", fn_name="do_count")

# Header
print("%-8s  " % "TIME", end="")
print("Method[counts]:ADDR (Ordered by counts)")

# Start print
while (1):
    try:
        sleep(interval)
    except KeyboardInterrupt:
        pass
        exit()

    print("%-8s  " % strftime("%H:%M:%S"), end="")
    counts = b.get_table("counts")

    i = 0
    result = ""
    for k, v in sorted(counts.items(), key=lambda counts: 0-counts[1].value):
    #reverse=True = 0-counts[0]
        result += "NO.%d:%s[%d]:%x  " % (i+1, b.ksym(k.ip), v.value, k.ip)
        i= i+1
        if i==10:
            break
    print(result)


