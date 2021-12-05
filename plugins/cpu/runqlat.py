#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @lint-avoid-python-3-compatibility-imports
#
# runqlat   Run queue (scheduler) latency as a histogram.
#           For Linux, uses BCC, eBPF.
#
# USAGE: runqlat [-h] [-T] [-m] [-P] [-L] [-p PID] [interval] [count]
#
# This measures the time a task spends waiting on a run queue for a turn
# on-CPU, and shows this time as a histogram. This time should be small, but a
# task may need to wait its turn due to CPU load.
#
# This measures two types of run queue latency:
# 1. The time from a task being enqueued on a run queue to its context switch
#    and execution. This traces ttwu_do_wakeup(), wake_up_new_task() ->
#    finish_task_switch() with either raw tracepoints (if supported) or kprobes
#    and instruments the run queue latency after a voluntary context switch.
# 2. The time from when a task was involuntary context switched and still
#    in the runnable state, to when it next executed. This is instrumented
#    from finish_task_switch() alone.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse


# for influxdb
import sys
sys.path.append('./plugins/common/')
from init_db import influx_client
from db_modules import write2db
from const import DatabaseType

from datetime import datetime



# arguments
examples = """examples:
    ./runqlat            # summarize run queue latency as a histogram
    ./runqlat 1 10       # print 1 second summaries, 10 times
    ./runqlat -mT 1      # 1s summaries, milliseconds, and timestamps
    ./runqlat -P         # show each PID separately
    ./runqlat -p 185     # trace PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Summarize run queue (scheduler) latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-P", "--pids", action="store_true",
    help="print a histogram per process ID")
# PID options are --pid and --pids, so namespaces should be --pidns (not done
# yet) and --pidnss:
parser.add_argument("--pidnss", action="store_true",
    help="print a histogram per PID namespace")
parser.add_argument("-L", "--tids", action="store_true",
    help="print a histogram per thread ID")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

typedef struct pid_key {
    u64 id;    // work around
    u64 delta;
    //char task[TASK_COMM_LEN];
} pid_key_t;

typedef struct pidns_key {
    u64 id;    // work around
    u64 delta;
    //char task[TASK_COMM_LEN];
} pidns_key_t;

typedef struct  original_data_key {
    u32 pid;
    u32 tgid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    u64 cpu;
} original_data_key_t;

BPF_HASH(start, u32);
STORAGE

struct rq;

// record enqueue timestamp
static int trace_enqueue(u32 tgid, u32 pid)
{
    if (FILTER || pid == 0)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}
"""

bpf_text_kprobe = """
int trace_wake_up_new_task(struct pt_regs *ctx, struct task_struct *p)
{
    return trace_enqueue(p->tgid, p->pid);
}

int trace_ttwu_do_wakeup(struct pt_regs *ctx, struct rq *rq, struct task_struct *p,
    int wake_flags)
{
    return trace_enqueue(p->tgid, p->pid);
}

// calculate latency
int trace_run(struct pt_regs *ctx, struct task_struct *prev)
{
    u32 pid, tgid;
    u64 timestamp;
    u32 cpu;

    // ivcsw: treat like an enqueue event and store timestamp
    if (prev->state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (!(FILTER || pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }

    tgid = bpf_get_current_pid_tgid() >> 32;
    pid = bpf_get_current_pid_tgid();
    cpu = bpf_get_smp_processor_id();
    if (FILTER || pid == 0)
        return 0;
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    timestamp= bpf_ktime_get_ns();
    delta = timestamp - *tsp;
    FACTOR

    // store as histogram
    STORE

    start.delete(&pid);
    return 0;
}
"""

bpf_text_raw_tp = """
RAW_TRACEPOINT_PROBE(sched_wakeup)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}

RAW_TRACEPOINT_PROBE(sched_wakeup_new)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}

RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 pid, tgid;
    u64 timestamp;
    u64 cpu;

    // ivcsw: treat like an enqueue event and store timestamp
    if (prev->state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (!(FILTER || pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }

    tgid = next->tgid;
    pid = next->pid;
    cpu=next->cpu;
    if (FILTER || pid == 0)
        return 0;
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    timestamp = bpf_ktime_get_ns();
    delta = timestamp - *tsp;
    FACTOR

    // store as histogram
    STORE


    start.delete(&pid);
    return 0;
}
"""

# data structure from template
class lmp_data(object):
    def __init__(self,a,b,c,d,e,f,g):
            self.time = a
            self.glob = b
            self.pid = c
            self.tgid = d
            self.comm = e
            self.cpu = f
            self.delta = g
                  
data_struct = {"measurement":'runqlat',
               "time":[],
               "tags":['glob',],
               "fields":['time','pid','tgid','comm','cpu','delta']}

is_support_raw_tp = BPF.support_raw_tracepoint()
if is_support_raw_tp:
    # bpf_text_raw_tp.replace('GET_COMM','bpf_probe_read_kernel_str(key.comm, sizeof(key.comm), next->comm);')
    bpf_text += bpf_text_raw_tp
else:
    # bpf_text_kprobe.replace('GET_COMM','bpf_get_current_comm(key.comm, sizeof(key.comm);')
    bpf_text += bpf_text_kprobe

# code substitutions
if args.pid:
    # pid from userspace point of view is thread group from kernel pov
    bpf_text = bpf_text.replace('FILTER', 'tgid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '0')
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
else:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"
if args.pids or args.tids:
    section = "pid"
    pid = "tgid"
    if args.tids:
        pid = "pid"
        section = "tid"
    bpf_text = bpf_text.replace('STORAGE',
        'BPF_HASH(dist, pid_key_t);')
    bpf_text = bpf_text.replace('STORE',
        'pid_key_t key = {.id = ' + pid + ', .delta = delta }; ' +
        'dist.increment(key);')

elif args.pidnss:
    section = "pidns"
    bpf_text = bpf_text.replace('STORAGE',
        'BPF_HASH(dist, pidns_key_t);')
    bpf_text = bpf_text.replace('STORE', 'pidns_key_t key = ' +
        '{.id = prev->nsproxy->pid_ns_for_children->ns.inum, ' +
        '.delta = delta}; dist.increment(key);')
    
else:
    #section = ""
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HASH(dist, original_data_key_t);')
    if is_support_raw_tp:
        bpf_text = bpf_text.replace('STORE',
            'original_data_key_t key; key.pid = pid;' + 'key.tgid= tgid;' +'bpf_probe_read_kernel_str(key.comm, sizeof(key.comm), next->comm);'+'key.cpu=cpu;'+
            'key.timestamp=timestamp;'+'dist.update(&key,&delta);')
    else:
        bpf_text = bpf_text.replace('STORE',
            'original_data_key_t key; key.pid = pid;' + 'key.tgid= tgid;' +'bpf_get_current_comm(key.comm, sizeof(key.comm);'+ 'key.cpu=cpu; '+
            'key.timestamp=timestamp;'+'dist.update(&key,&delta);')




if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)
if not is_support_raw_tp:
    b.attach_kprobe(event="ttwu_do_wakeup", fn_name="trace_ttwu_do_wakeup")
    b.attach_kprobe(event="wake_up_new_task", fn_name="trace_wake_up_new_task")
    b.attach_kprobe(event_re="^finish_task_switch$|^finish_task_switch\.isra\.\d$",
                    fn_name="trace_run")

print("Tracing run queue latency... Hit Ctrl-C to end.")

# output
exiting = 0 if args.interval else 1
dist = b.get_table("dist")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    #dist_test.print_log2_hist(label, section, section_print_fn=int)
    for k,v in dist.items():
        # print("start_time: %-15d pid:%-5d  tgid:%-5d comm:%-15s delta:%-5d" %(k.timestamp,k.pid,k.tgid,k.comm,v.value))
        # write to influxdb
        test_data = lmp_data(datetime.now().isoformat(),'glob',k.pid,k.tgid,k.comm,k.cpu, v.value)
        #print(test_data)
        write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()
