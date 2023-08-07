#!/bin/python3
from inspect import stack
import time
from bcc import BPF
import argparse
from signal import signal, SIG_IGN

# arguments
examples = """examples:
    ./load_monitor.py             # monitor system load until Ctrl-C
    ./load_monitor.py -t 5           # monitor for 5 seconds only
"""

def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")
    if ival <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

parser = argparse.ArgumentParser(
    description="Summarize on-CPU time by stack trace",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--time", default=99999999, dest="time",
                    type=positive_int, help="running time")
args = parser.parse_args()

code = """
#include <linux/sched.h>
#define LOAD_LIMIT 4
typedef struct {
    raw_spinlock_t lock;
    unsigned int nr_running;
} Rq;
typedef struct {
    u64 stackid;
    char comm[TASK_COMM_LEN];
} TaskData;
BPF_STACK_TRACE(stack_trace, 128);
BPF_HASH(stack_count, u32, u32, 128);
BPF_HASH(pid_data, u32, TaskData);
void kprobe__update_rq_clock(struct pt_regs *ctx) {
    Rq rq;
    TaskData td;
    u32 pid;
    int stackid;
    bpf_probe_read_kernel(&rq, sizeof(Rq), (void*)PT_REGS_PARM1(ctx));
    if(rq.nr_running > LOAD_LIMIT) {
        stackid = stack_trace.get_stackid(ctx, 0);
        if(stackid < 0) return;
        td.stackid = stackid;
        stack_count.increment(td.stackid);
        bpf_get_current_comm(td.comm, TASK_COMM_LEN);
        pid = bpf_get_current_pid_tgid();
        pid_data.update(&pid, &td);
    }
}
"""

bpf = BPF(text=code)
stack_trace = bpf["stack_trace"]
stack_count = bpf["stack_count"]
pid_data = bpf["pid_data"]

def sig_handle(*_):
    with open("stack.bpf", "w") as file:
        for k, v in stackcount.items():
            file.write("@[\n")
            for i in stack_trace.walk(k):
                file.write(bpf.ksym(i).decode()+"\n")
            file.write("]: %d\n" % v)
    import os
    os.system("FlameGraph/stackcollapse-bpftrace.pl stack.bpf | FlameGraph/flamegraph.pl > stack.svg")
    print("\b\bQuit...\n")
    exit()

signal(2, sig_handle)
signal(1, sig_handle)
for _ in range(args.time//5):
    time.sleep(5)
    stackid = [(v.stackid, k.value) for k, v in pid_data.items()]
    stackcount = {k.value: v.value for k, v in stack_count.items()}
    piddata = {k.value: v.comm.decode() for k, v in pid_data.items()}
    stacktrace = {k: stack_trace.walk(k) for k in stackcount.keys()}
    stackid.sort()
    timestr = time.strftime("%H:%M:%S")
    if (l := len(stackid)) > 0:
        for i in range(0, l):
            if i == 0 or stackid[i][0] != stackid[i-1][0]:
                id = stackid[i][0]
                print("_"*60)
                for j in stacktrace[id]:
                    print("%#08x %s" % (j, bpf.ksym(j).decode()))
                print("%-10s %-6s %-6s %-16s" %
                        ("stackid", "count", "pid", "comm"))
                print("%-10d %-6d" % (id, stackcount[id]))
            id = stackid[i][1]
            print("%-10s %-6s %-6d %-16s" %
                    ("", "", id, piddata[id]))
        print("_"*26 + timestr + "_"*26)
        print()
signal(2, SIG_IGN)
signal(1, SIG_IGN)
sig_handle()

