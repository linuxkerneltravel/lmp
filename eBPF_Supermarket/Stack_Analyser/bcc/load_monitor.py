#!/bin/python3

'''
Copyright 2023 The LMP Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

author: luiyanbing@foxmail.com

高负载进程调用栈监控脚本
'''

from time import time, sleep, strftime
from signal import signal, SIG_IGN


def nice_1():
    from os import nice
    nice(-20)

nice_1()

mem_path = "/dev/shm/load_monitor_tex.pkl"

def get_args():
    from argparse import ArgumentParser, ArgumentTypeError, RawDescriptionHelpFormatter
    # arguments
    examples = """examples:
        ./load_monitor.py             # monitor system load until Ctrl-C
        ./load_monitor.py -t 5           # monitor for 5 seconds only
    """

    def positive_int(val):
        try:
            ival = int(val)
        except ValueError:
            raise ArgumentTypeError("must be an integer")
        if ival <= 0:
            raise ArgumentTypeError("must be positive")
        return ival


    parser = ArgumentParser(
        description="Summarize on-CPU time by stack trace",
        formatter_class=RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-t", "--time", default=99999999, dest="time",
                        type=positive_int, help="running time")
    parser.add_argument("-F", "--frequency", default=99, dest="freq",
                        type=positive_int, help="monitor frequency")
    parser.add_argument("-d", "--delay", default=10, dest="delay",
                        type=positive_int, help="output delay(interval)")
    parser.add_argument("-l", "--threshold", default=8, dest="threshold",
                        type=positive_int, help="load limit threshold")
    # parser.add_argument("-f", "--flame-graph", action='store_true', dest="flame")
    parser.add_argument("-r", "--report", action='store_true', dest="report")
    return parser.parse_args()

args = get_args()


def save_fla(tex):
    from subprocess import Popen, PIPE
    p = Popen("flamegraph.pl > stack.svg", shell=True, stdin=PIPE)
    p.stdin.write(tex.encode())
    p.stdin.close()
    p.wait()

if args.report:
    with open(mem_path, "r") as file:
        print(file.read())
    # if args.flame:
    #     save_fla(tex)
    # else:
    from os import remove
    remove(mem_path)
    exit()

code = """
#include <linux/sched.h>
#define LOAD_LIMIT LOAD_LIMIT_THRESHOLD
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

def get_load(code):
    from subprocess import Popen, PIPE
    p = Popen("sudo cat /proc/kallsyms | grep ' avenrun'", shell=True, stdout=PIPE)
    p.wait()
    evanrun_addr = "0x" + p.stdout.read().split()[0].decode()
    # print("get addr of evanrun: ", evanrun_addr)
    return code.replace("AVENRUN_ADDR", evanrun_addr)

code = get_load(code)
code = code.replace("LOAD_LIMIT_THRESHOLD", str(args.threshold))
# !!!segfault
# import ctypes
# addr = int(evanrun_addr, base=16)
# load = ctypes.cast(addr, ctypes.POINTER(ctypes.c_ulong)).contents

def attach_bpf():
    from bcc import BPF, PerfType, PerfSWConfig
    bpf = BPF(text=code)
    bpf.attach_perf_event(ev_type=PerfType.SOFTWARE,
                        ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_stack",
                        sample_period=0, sample_freq=args.freq)
    return bpf

bpf = attach_bpf()

def detach_bpf(bpf):
    from bcc import BPF, PerfType, PerfSWConfig
    bpf.detach_perf_event(ev_type=PerfType.SOFTWARE,
                          ev_config=PerfSWConfig.CPU_CLOCK)

def format_tex():
    stackcount = {TaskData(k): v.value for k,
                    v in bpf["stack_count"].items()}
    bpf["stack_count"].clear()
    stackcount = sorted(stackcount.items(),
                        key=lambda d: d[1], reverse=False)
    timestr = strftime("%H:%M:%S")
    tex = ''
    for d in stackcount:
        tex += "_"*32+'\n'
        tex += "%-5d:%16s %d\n" % (d[0].pid, d[0].comm, d[1])
        if d[0].ksid >= 0:
            for j in bpf["stack_trace"].walk(d[0].ksid):
                tex += "\t%#08x %s\n" % (j, bpf.ksym(j).decode())
        else:
            tex += "\t[MKS]\n"
        tex += "\t"+"-"*16 + '\n'
        if d[0].usid >= 0:
            for j in bpf["stack_trace"].walk(d[0].usid):
                tex += "\t%#08x %s\n" % (j, bpf.sym(j, d[0].pid).decode())
        else:
            tex += "\t[MUS]\n"
    tex += "_"*26 + timestr + "_"*26 + '\n'
    return tex

def fla_tex():
    stackcount = {TaskData(k): v.value for k,
                  v in bpf["stack_count"].items()}
    bpf["stack_count"].clear()
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
            line = "[MKS];" + line
        line = "-"*16+';' + line
        deep = 0
        if (k.usid >= 0):
            for i in bpf["stack_trace"].walk(k.usid):
                line = bpf.sym(i, k.pid).decode()+";" + line
                deep += 1
        else:
            line = "[MUS];" + line
            deep = 1
        line = '.;'*(max_deep - deep) + line
        line = '%s:%d;' % (k.comm, k.pid) + line
        line += " %d\n" % v
        tex += line
    return tex

class TaskData:
    def __init__(self, a) -> None:
        self.pid = a.pid
        self.ksid = a.ksid
        self.usid = a.usid
        self.comm = a.comm.decode()

mem_file = open(mem_path, "a")

def sig_handle(*_):
    print("\b\bQuit...\n")
    detach_bpf(bpf)
    # tex = format_tex()
    # print(tex, file=mem_file)
    mem_file.close()
    exit()

signal(2, sig_handle)
signal(1, sig_handle)
start = 0.
load = bpf["load"]
period = 1/(args.freq + 1)
print("start...")

for _ in range(args.time):
    load_5 = int(load[0].value)
    # print(load_5, end=' ')
    if (load_5 < args.threshold):
        sleep(period)
    elif (time()-start > args.delay):
        # print(".")
        sleep(period*100)
        tex = format_tex()
        print(tex, file=mem_file)
        start = time()
    else:
        sleep(args.delay)

signal(2, SIG_IGN)
signal(1, SIG_IGN)
sig_handle()