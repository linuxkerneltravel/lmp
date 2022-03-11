#!/usr/bin/env python3
# -*- coding:utf-8 -*-
from __future__ import print_function
from bcc import BPF
old_pid="123"
VM_READ     = 0x00000001
VM_WRITE    = 0x00000002
VM_EXEC     = 0x00000004
VM_MAYSHAER = 0x00000080
# load BPF program
bpf_text ="""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/sysinfo.h>
#include <uapi/linux/kernel.h>
#include <linux/seq_file.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    u64 start;
    u64 end;
    u64 flags;
    u32 pid;
    char comm[TASK_COMM_LEN];
};
int do_return(struct pt_regs *ctx, struct seq_file *m,unsigned long start,unsigned long end,unsigned long flags) {
  
    struct data_t data = {};
    data.start=start;
    data.end=end;
    data.flags=flags;
    data.pid=bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));


    events.perf_submit(ctx, &data, sizeof(data));
    return 0; 
}

"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="show_vma_header_prefix", fn_name="do_return")
def print_event(cpu, data, size):
    event = b["events"].event(data)
    flags=bin(event.flags)
    
    #flags_read=int(flags,2) & int(bin(VM_READ),2)
    flags_read     = "r" if int(flags,2) & int(bin(VM_READ),2) else "-"
    flags_write    = "w" if int(flags,2) & int(bin(VM_WRITE),2) else "-"
    flags_exec     = "x" if int(flags,2) & int(bin(VM_EXEC),2) else "-"
    flags_mayshaer = "s" if int(flags,2) & int(bin(VM_MAYSHAER),2) else "p"
    size=(event.end-event.start)/1024
    global old_pid
    if(event.pid!=old_pid):
        print("pid:%-10s   comm:%-10s"%(event.pid,event.comm))
        old_pid=event.pid
    print("%-10x - %-10x %10x  %s%s%s%s %8sK"%(event.start,event.end,event.flags,flags_read,flags_write,flags_exec,flags_mayshaer,size)) 
    
print("Tracing for sysinfo... Ctrl-C to end")
print("%-15s %-15s %-13s %s"%("start","end","flags","size"))  

# format output
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
    
