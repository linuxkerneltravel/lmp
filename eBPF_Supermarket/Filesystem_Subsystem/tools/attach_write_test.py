#!/usr/bin/python
# a test for 3 differnet kinds of write syscall attach 

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime

bpf_text = """
#include <uapi/linux/ptrace.h>

enum stat_types {
    S_VFS = 1,
    S_GET,
    S_X86,
    S_MAXSTAT
};

BPF_ARRAY(stats, u64, S_MAXSTAT);

static void stats_increment(int key) {
    stats.atomic_increment(key);
}


void do_vfs(struct pt_regs *ctx) { stats_increment(S_VFS); }
void do_get(struct pt_regs *ctx) { stats_increment(S_GET); }
void do_x86(struct pt_regs *ctx) { stats_increment(S_X86); }
"""

b = BPF(text=bpf_text)
fnname_write = b.get_syscall_prefix().decode() + 'write'
b.attach_kprobe(event="vfs_write",  fn_name="do_vfs")
b.attach_kprobe(event=fnname_write ,fn_name="do_get")
b.attach_kprobe(event="__x64_sys_write",  fn_name="do_x86")

# stat column labels and indexes
stat_types = {
    "VFS": 1,
    "GET": 2,
    "X86": 3
}

# header
print("%-8s  " % "TIME", end="")
for stype in stat_types.keys():
    print(" %8s" % (stype), end="")
    idx = stat_types[stype]
print("")

# output
interval = 1
while (1):
    try:
        sleep(interval)
    except KeyboardInterrupt:
        pass
        exit()

    print("%-8s " % strftime("%H:%M:%S"), end="")
    # print each statistic as a column
    for stype in stat_types.keys():
        idx = stat_types[stype]
        try:
            val = b["stats"][c_int(idx)].value / interval
            print(" %8d" % val, end="")
        except:
            print(" %8d" % 0, end="")
    b["stats"].clear()
    print("")
