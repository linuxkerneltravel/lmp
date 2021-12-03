#!/usr/bin/env python3
# -*- coding:utf-8 -*-
from __future__ import print_function
from bcc import BPF
import time

event_pid=0
event_comm=""
old_pid=0
count = 0
bpf_text ="""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/kernel.h>
#include <linux/sched.h>
BPF_PERF_OUTPUT(events);
struct data_t {
    char comm[TASK_COMM_LEN];
    u32 pid;
};
int do_return(struct pt_regs *ctx, struct sysinfo *req) {
    
    struct data_t data = {};
    u32 pid;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&data.comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid();
    
    
    data.pid=pid;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;    
}

"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="swap_readpage", fn_name="do_return")

#format output
 
def print_event(cpu, data, size):
    event = b["events"].event(data)
    global event_pid,event_comm,old_pid,count
    if(event.pid!=old_pid):
        old_pid=event.pid
        event_pid=event.pid
        event_comm=event.comm
        timenow = time.strftime("%H:%M:%S", time.localtime())#%Y-%m-%d %H:%M:%S
        print("PID: %-15s -  Comm: %-10s - Time: %-10s "%(event_pid,event_comm,timenow))
        if(count!=0):
            count=0    
    else:    
        count=count+1
    
    
    
    
print("Tracing for swap-in... Ctrl-C to end")

# format output
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
        print("count:%s total:%s Kb"%(count+1,(count+1)*4))
    except KeyboardInterrupt:
        exit()
    
