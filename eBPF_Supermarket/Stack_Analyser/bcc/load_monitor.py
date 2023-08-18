#!/bin/python3
import time
from signal import signal, SIG_IGN
from bcc import BPF, PerfType, PerfSWConfig
from subprocess import Popen, PIPE
import argparse

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
parser.add_argument("-F", "--frequency", default=99, dest="freq",
                    type=positive_int, help="monitor frequency")
parser.add_argument("-d", "--delay", default=10, dest="delay",
                    type=positive_int, help="output delay(interval)")
args = parser.parse_args()

code = """
#include <linux/sched.h>
#define LOAD_LIMIT 4
#define MAX_ENTITY 10240
#define avenrun AVENRUN_ADDRULL
typedef struct {
    int pid, usid, ksid, o;
    char comm[TASK_COMM_LEN];
} TaskData;
BPF_STACK_TRACE(stack_trace, MAX_ENTITY);
BPF_HASH(stack_count, TaskData, u32, MAX_ENTITY);
BPF_ARRAY(load, unsigned long, 1);
void do_stack(struct pt_regs *ctx) {
    unsigned long avg_load;
    bpf_probe_read_kernel(&avg_load, sizeof(avg_load), (void *)avenrun);
    avg_load >>= 11;
    int zero = 0;
    load.update(&zero, &avg_load);
    if(avg_load >= LOAD_LIMIT) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();

        TaskData td = {
            .pid = bpf_get_current_pid_tgid() >> 32,
            .ksid = stack_trace.get_stackid(ctx, BPF_F_FAST_STACK_CMP),
            .usid = stack_trace.get_stackid(ctx, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP),
            .o = 0,
        };
        bpf_get_current_comm(td.comm, TASK_COMM_LEN);
        stack_count.increment(td);
    }
}
"""

p = Popen("sudo cat /proc/kallsyms | grep ' avenrun'", shell=True, stdout=PIPE)
p.wait()
evanrun_addr = "0x" + p.stdout.read().split()[0].decode()
# print("get addr of evanrun: ", evanrun_addr)
code = code.replace("AVENRUN_ADDR", evanrun_addr)

# !!!segfault
# import ctypes
# addr = int(evanrun_addr, base=16)
# load = ctypes.cast(addr, ctypes.POINTER(ctypes.c_ulong)).contents

bpf = BPF(text=code)
bpf.attach_perf_event(ev_type=PerfType.SOFTWARE,
                      ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_stack",
                      sample_period=0, sample_freq=args.freq)

def sig_handle(*_):
    print("\b\bQuit...\n")
    bpf.detach_perf_event(ev_type=PerfType.SOFTWARE,
                          ev_config=PerfSWConfig.CPU_CLOCK)
    stackcount = {TaskData(k): v.value for k,
                  v in bpf["stack_count"].items()}

    max_deep = 0
    for k in stackcount.keys():
        if (k.usid >= 0):
            deep = 0
            for _ in bpf["stack_trace"].walk(k.usid):
                deep += 1
            if max_deep < deep:
                max_deep = deep
    tex = ''
    for k, v in stackcount.items():
        line = ''
        if (k.ksid >= 0):
            for i in bpf["stack_trace"].walk(k.ksid):
                line = bpf.ksym(i).decode()+';' + line
        else:
            line = "[MISSING KERNEL STACK];" + line
        line = "-"*16+';' + line
        deep = 0
        if (k.usid >= 0):
            for i in bpf["stack_trace"].walk(k.usid):
                line = bpf.sym(i, k.pid).decode()+";" + line
                deep += 1
        else:
            line = "[MISSING USER STACK];" + line
            deep = 1
        line = '.;'*(max_deep - deep) + line
        line = '%s:%d;' % (k.comm, k.pid) + line
        line += " %d\n" % v
        tex += line
    from subprocess import Popen, PIPE
    p = Popen("flamegraph.pl > stack.svg", shell=True, stdin=PIPE)
    p.stdin.write(tex.encode())
    p.stdin.close()
    p.wait()
    exit()


class TaskData:
    def __init__(self, a) -> None:
        self.pid = a.pid
        self.ksid = a.ksid
        self.usid = a.usid
        self.comm = a.comm.decode()


signal(2, sig_handle)
signal(1, sig_handle)
start = 0.
load = bpf["load"]
period = 1/(args.freq + 1)
for _ in range(args.time):
    load_5 = int(load[0].value)
    # print(load_5, end=' ')
    if (load_5 < 4):
        time.sleep(period)
    elif (time.time()-start > args.delay):
        tex = ''
        time.sleep(1)
        stackcount = {TaskData(k): v.value for k,
                      v in bpf["stack_count"].items()}
        stackcount = sorted(stackcount.items(),
                            key=lambda d: d[1], reverse=False)
        timestr = time.strftime("%H:%M:%S")
        for d in stackcount:
            tex += "_"*32+'\n'
            tex += "%-5d:%16s %d\n" % (d[0].pid, d[0].comm, d[1])
            if d[0].ksid >= 0:
                for j in bpf["stack_trace"].walk(d[0].ksid):
                    tex += "\t%#08x %s\n" % (j, bpf.ksym(j).decode())
            else:
                tex += "\t[MISSING KERNEL STACK]\n"
            tex += "\t"+"-"*16 + '\n'
            if d[0].usid >= 0:
                for j in bpf["stack_trace"].walk(d[0].usid):
                    tex += "\t%#08x %s\n" % (j, bpf.sym(j, d[0].pid).decode())
            else:
                tex += "\t[MISSING USER STACK]\n"
        tex += "_"*26 + timestr + "_"*26 + '\n'
        print(tex)
        start = time.time()
    else:
        time.sleep(args.delay)

signal(2, SIG_IGN)
signal(1, SIG_IGN)
sig_handle()