#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime

# for influxdb
import sys
sys.path.append('./plugins/common/')
from init_db import influx_client
from db_modules import write2db
from const import DatabaseType

from datetime import datetime



bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 cpu;
    u32 pid;
    u32 tgid;
};

BPF_HASH(start, struct key_t);
BPF_HASH(dist, struct key_t);

int switch_start(struct pt_regs *ctx)
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

int switch_end(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    struct key_t key;
    u64 *value;
    u64 delta;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = prev->pid;
    key.tgid = prev->tgid;

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

# data structure from template
class lmp_data(object):
    def __init__(self,a,b,c,d,e):
            self.time = a
            self.glob = b
            self.cpu = c
            self.pid = d
            self.duration = e
                    

data_struct = {"measurement":'taskswitch',
               "time":[],
               "tags":['glob','cpu','pid',],
               "fields":['duration']}

b = BPF(text=bpf_text)
b.attach_kretprobe(event="pick_next_task_fair", fn_name="switch_start")
b.attach_kretprobe(event="pick_next_task_idle", fn_name="switch_start")
b.attach_kretprobe(event="pick_next_task_rt", fn_name="switch_start")
b.attach_kretprobe(event="pick_next_task_dl", fn_name="switch_start")
b.attach_kretprobe(event="pick_next_task_stop", fn_name="switch_start")

b.attach_kprobe(event="finish_task_switch", fn_name="switch_end")

dist = b.get_table("dist")

#print("%-6s%-6s%-6s%-6s" % ("CPU", "PID", "TGID", "TIME(ns)"))

while (1):
    try:
        sleep(1)
        for k, v in dist.items():
            #print("%-6d%-6d%-6d%-6d" % (k.cpu, k.pid, k.tgid, v.value))
            test_data = lmp_data(datetime.now().isoformat(),'glob', k.cpu, k.pid, v.value)
            write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
        dist.items()
    except KeyboardInterrupt:
        exit()

