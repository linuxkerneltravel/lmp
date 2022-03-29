#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# oomkill   Trace oom_kill_process(). For Linux, uses BCC, eBPF.
#
# This traces the kernel out-of-memory killer, and prints basic details,
# including the system load averages. This can provide more context on the
# system state at the time of OOM: was it getting busier or steady, based
# on the load averages? This tool may also be useful to customize for
# investigations; for example, by adding other task_struct details at the time
# of OOM.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 09-Feb-2016   Brendan Gregg   Created this.

from bcc import BPF
from time import strftime


# for influxdb
import sys
sys.path.append('./plugins/common/')
from init_db import influx_client
from const import DatabaseType
from db_modules import write2db

from datetime import datetime
# linux stats
loadavg = "/proc/loadavg"

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/oom.h>

struct data_t {
    u32 fpid;
    u32 tpid;
    u64 pages;
    char fcomm[TASK_COMM_LEN];
    char tcomm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

void kprobe__oom_kill_process(struct pt_regs *ctx, struct oom_control *oc, const char *message)
{
    unsigned long totalpages;
    struct task_struct *p = oc->chosen;
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.fpid = pid;
    data.tpid = p->pid;
    data.pages = oc->totalpages;
    bpf_get_current_comm(&data.fcomm, sizeof(data.fcomm));
    bpf_probe_read_kernel(&data.tcomm, sizeof(data.tcomm), p->comm);
    events.perf_submit(ctx, &data, sizeof(data));
}
"""

# data structure from template
class lmp_data(object):
    def __init__(self,a,b,c,d,e,f,g,h):
            self.time = a
            self.glob = b
            self.fpid = c
            self.tpid = d
            self.pages = e
            self.fcomm = f
            self.tcomm = g
            self.avgline = h
            
                    
data_struct = {"measurement":'oomkill',
               "time":[],
               "tags":['glob',],
               "fields":['time','fpid','tpid','pages','fcomm','tcomm','avgline']}


# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    with open(loadavg) as stats:
        avgline = stats.read().rstrip()
        
    test_data = lmp_data(datetime.now().isoformat(),'glob',event.fpid,event.tpid,  event.pages,event.fcomm.decode('utf-8', 'replace'),  event.tcomm.decode('utf-8', 'replace'), avgline)
    
    write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
        
        
   # print(("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\")"
   #    ", %d pages, loadavg: %s") % (strftime("%H:%M:%S"), event.fpid,
   #    event.fcomm.decode('utf-8', 'replace'), event.tpid,
   #     event.tcomm.decode('utf-8', 'replace'), event.pages, avgline))

# initialize BPF
b = BPF(text=bpf_text)
print("Tracing OOM kills... Ctrl-C to stop.")
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
