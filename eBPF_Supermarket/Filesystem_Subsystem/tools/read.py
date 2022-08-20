#!/usr/bin/python
# monitoring read syscall
#
# Print processes and PID which call read method and ordered by counts 
# ADDR parent child user pr ?
# Based on hello_perf_output.py(bcc)
#
# version 1.0

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from ctypes import c_int
from time import sleep, strftime
import pwd

# Print interval
interval = 2

# Debug C prog
debug = 0

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/mm.h>

//for per_output
struct data_t
{
    u32 pid;
    u32 uid;
    //u64 ts;
    char comm[TASK_COMM_LEN];
    u64 s_addr;
    u64 e_addr;
    int pr;
};

BPF_PERF_OUTPUT(events);
"""

bpf_text_kprobe = """
int trace_syscall_read(struct pt_regs *ctx) 
{
    struct data_t data = {};
    struct task_struct *tp;
    struct mm_struct *mm;
    struct passwd *pw; 

    data.pid = bpf_get_current_pid_tgid();
    //if type is u64 use:>>32

    data.uid = bpf_get_current_uid_gid();
    //how turn uid to name?
    /*pw = getpwuid((uid_t)(data.uid));
    data.user = pw->pw_name;
    //ERROR:implicit declaration of function 'getpwuid' is invalid
    */

    //data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    tp = (struct task_struct*)bpf_get_current_task();
    //u64 bpf_get_current_task(void):
    //Return a pointer to the current task struct.
    
    //tp=pid_task((data.pid),PIDTYPE_PID);
    mm = tp->mm;
    data.s_addr = mm->mmap->vm_start;
    data.e_addr = mm->mmap->vm_end;
    data.pr = tp->prio;

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

bpf_text += bpf_text_kprobe

if debug:
    print(bpf_text)

# Initalize b
b = BPF(text=bpf_text)
fnname_read = b.get_syscall_prefix().decode() + 'read'
b.attach_kprobe(event=fnname_read,fn_name="trace_syscall_read")

# Define process event
# fd = open("out.txt", "w")
def print_event(cpu, data, size):
    global dic
    event = b["events"].event(data)

    str = "%-s, %-d, %s[%-d], %d 0x%lx-0x%lx" % \
    (event.comm, event.pid, pwd.getpwuid(event.uid)[0] ,event.uid,  event.pr, event.s_addr, event.e_addr)
    if dic.get(str,-1) == -1:
        dic[str]=1
    else:
        dic[str]+=1
        

# Column labels and indexes
header = (
    "Counts",
    "Common",
    "PID",
    "USER",
    "PR  "
    "VMADDR",
) 
# Use the header{} made printing disordered

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
dic = {}

while 1:
    try:
        sleep(interval)
        b.perf_buffer_poll()
        
    # Header
        print("%-10s" % strftime("%H:%M:%S"), end="")
        for h in header:
            print("%-8s" % (h), end="")
        print("")

        i = 0
        #for k, v in dic.items():
        for k, v in sorted(dic.items(), key=lambda item:item[1], reverse=True):
            i += 1
            print("NO.%-8d" % (i), end="")
            print(b"%-8d%s" % (v, k))
        dic = {}
        print("\n")
    except KeyboardInterrupt:
        pass
        exit()