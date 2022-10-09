#!/usr/bin/python
# monitoring read syscall
#
# Print processes and PID which call read method and ordered by counts 
# ADDR parent child user pr ?
# Based on hello_perf_output.py(bcc)
#
# version 2.0

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from ctypes import c_int
from time import sleep, strftime
import pwd

# Print interval
interval = 2
print("Print Read/Write syscall counts and info every %ds" % interval)

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/mm.h>

//char self[] = "rw.py";

struct key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 uid;
    u8 pr;
    u64 s_addr;
    u64 e_addr;
    char flag;
};

BPF_HASH(counts, struct key_t, u64);

static void counts_increment(struct key_t key) {
    counts.atomic_increment(key);
}

int trace_syscall_read(struct pt_regs *ctx) 
{
    struct key_t key = {};
    struct task_struct *tp;
    struct mm_struct *mm;

    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    u32 pid = bpf_get_current_pid_tgid();
    u32 uid = bpf_get_current_uid_gid();
    tp = (struct task_struct*)bpf_get_current_task();
    u8 pr = tp->prio;
    mm = tp->mm;
    u64 s_addr = mm->mmap->vm_start;
    u64 e_addr = mm->mmap->vm_end;
    char flag = 'R';

    key.pid = pid;
    key.uid = uid;
    key.pr = pr;
    key.s_addr = s_addr;
    key.e_addr = e_addr;
    key.flag = flag;

    counts_increment(key);

    return 0;
}

int trace_syscall_write(struct pt_regs *ctx) 
{
    struct key_t key = {};
    struct task_struct *tp;
    struct mm_struct *mm;

    bpf_get_current_comm(&key.comm, sizeof(key.comm));


    u32 pid = bpf_get_current_pid_tgid();
    u32 uid = bpf_get_current_uid_gid();
    tp = (struct task_struct*)bpf_get_current_task();
    u8 pr = tp->prio;
    mm = tp->mm;
    u64 s_addr = mm->mmap->vm_start;
    u64 e_addr = mm->mmap->vm_end;
    char flag = 'W';

    key.pid = pid;
    key.uid = uid;
    key.pr = pr;
    key.s_addr = s_addr;
    key.e_addr = e_addr;
    key.flag = flag;

    counts_increment(key);

    return 0;
}
"""

# Initalize b
b = BPF(text=bpf_text)
fnname_read = b.get_syscall_prefix().decode() + 'read'
fnname_write = b.get_syscall_prefix().decode() + 'write'
b.attach_kprobe(event=fnname_read,fn_name="trace_syscall_read")
b.attach_kprobe(event=fnname_write,fn_name="trace_syscall_write")

# Column labels
header = (
    "Counts",
    "FLAG",
    "COMM",
    "PID",
    "USER",
    "PR",
    "VMADDR",
) 

# outpu
while (1):
    try:
        sleep(interval)
    except KeyboardInterrupt:
        pass
        exit()

    print("%-9s" % strftime("%H:%M:%S"), end="")
    for h in header:
        print("%-9s" % (h), end="")
    print("")

    counts = b.get_table("counts")
    i = 0
    for k, v in sorted(counts.items(), key=lambda counts:counts[1].value, reverse=True):
        i += 1
        print("NO.%-8d" % (i) ,end="")
        print("%-8d" % v.value ,end="")
        print("%-8s" % k.flag ,end="")
        print("%-8s" % k.comm ,end="")
        print("%-8d" % k.pid ,end="")
        print("%-8s" % pwd.getpwuid(k.uid)[0],end="")
        print("%-8d" % k.pr ,end="")
        print("0x%-8lx-" % k.s_addr ,end="")
        print("0x%-8lx" % k.e_addr)

        if i==10:
            break
    print("")
    