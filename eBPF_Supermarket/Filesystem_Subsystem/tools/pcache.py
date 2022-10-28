#!/usr/bin/python
# monitoring pagecache hit ratio
#
# Count pagecache hit ratio by specific interval and miss info
# Based on dcstat(bcc)
#
# version 1.0

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime
import pwd
import argparse

# Print interval
interval = 1
print("Print pagecache hit ratio every %ds" % interval)
print("'-m' to show the miss info.")
print("------------------------------------------------")

# arguments
examples = """examples:
    ./pcache           # trace pagecache hit ratio
    ./pcache -a        # trace failed pcache info
"""
parser = argparse.ArgumentParser(
    description="Trace pagecache hit ratio",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-m", "--miss", action="store_true",
    help="trace failed pcache info")
args = parser.parse_args()

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

# define TASK_COMM_LEN      16

// for key and table's length
enum stats {
    S_ALL = 1,
    S_HIT,
    S_MISS,
    S_MAXSTAT
};

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
};

// to save counts in each stats
BPF_ARRAY(counts, u64, S_MAXSTAT);
// to save miss info, ts as key
BPF_HASH(info, u64, struct data_t);

// must be "static"
static void counts_increment(int key) {
    counts.atomic_increment(key);
}

// in the entry of pagecache_get_page  
int count_total(struct pt_regs *ctx) {
    int key = S_ALL;
    counts_increment(key);

    return 0;
}

// in the exit of pagecache_get_page
int count_hit(struct pt_regs *ctx) {
    if (PT_REGS_RC(ctx) != 0)
    {
        int key = S_HIT;
        counts_increment(key);
    }
    else
    {
        int key = S_MISS;
        counts_increment(key);

        struct data_t data = {};
        u32 pid = bpf_get_current_pid_tgid();
        u32 uid = bpf_get_current_uid_gid();
        u64 ts  = bpf_ktime_get_ns();
        
        data.pid = pid;
        data.uid = uid;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        info.update(&ts, &data);
    }
    
    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="pagecache_get_page", fn_name="count_total")
b.attach_kretprobe(event="pagecache_get_page", fn_name="count_hit")

# print header
stats = {
    "ALL": 1,
    "HIT": 2,
    "MISS": 3
}
header = {
    "UID": 1,
    "USER": 2,
    "PID": 3,
    "COMM": 4
}

print("%-8s  " % "TIME", end="")
for h, idx in sorted(stats.items(), key=lambda k_v: (k_v[1], k_v[0])):
    print(" %8s" % h, end="")
print(" %9s" % "RATIO")

# for no args
def print_ratio():
    print("%-8s " % strftime("%H:%M:%S"), end="")

    # print each statistic as a column
    for stype, idx in sorted(stats.items(), key=lambda k_v: (k_v[1], k_v[0])):
        try:
            val = b["counts"][c_int(idx)].value / interval
            print(" %8d" % val, end="")
        except:
            print(" %8s" % "/", end="")

    # print hit ratio percentage
    try:
        all = b["counts"][c_int(stats["ALL"])].value
        hit = b["counts"][c_int(stats["HIT"])].value
        pct =  float(100) * hit / all 
        print(" %9.1f%%" % pct)
    except:
        print(" %8s" % "-")

    b["counts"].clear()    

# for args '-m'
def print_info():
    info = b.get_table("info")
    leng = len(info)
    if leng > 0:
        print("Miss_info:")
        print("%-18s" % ("TS(s)"), end="")
        for h,idx in sorted(header.items(), key=lambda k_v: (k_v[1], k_v[0])):
            print("%-8s" % (h), end="")
        print()

        for k, v in sorted(info.items(), key=lambda info:info[0].value):
            try:
                print("%-18d" % k.value ,end="")
                print("%-8d" % v.uid ,end="")
                print("%-8s" % pwd.getpwuid(v.uid)[0],end="")                
                print("%-9d" % v.pid ,end="")
                print("%-18s" % v.comm,end="")
                print()
            except:
                print(" %9s" % "/", end="")
        print()

    b["info"].clear()

# output
while True:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        pass
        exit()

    print_ratio()

    if args.miss:
        print_info()
