#!/usr/bin/python
# monitoring write syscall
#
# Print processes and PID which call write method and ordered by counts 
# 
# Based on opensnoopy(bcc)
#
# version 2.0

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from ctypes import c_int
from time import sleep, strftime
import pwd
import os
import argparse

# arguments
examples = """examples:
    ./write          # trace file write info
    ./write -c       # trace TOP10 info
"""
parser = argparse.ArgumentParser(
    description="Trace file write info",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-c", "--count", action="store_true",
    help="show TOP10 info ordered by counts")
args = parser.parse_args()

# Get pid
self = os.getpid()
print('Pid: ', self)
sleep(1)

# Print interval
interval = 1

def title():
    print("Print file write info" )
    print("'-c' to show TOP10 info every %ds ordered by counts." % interval)
    print("---------------------------------------------------")
    sleep(1)

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/fs.h>

# define FNAME_MAX 64

//for hash table
struct val_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    int pr;
    int fd;
    ssize_t ret; //return Nbytes if success,else -1
    char fstype[FNAME_MAX];
};

struct tmp_t
{
    int fd;
    ssize_t ret; 

};

BPF_HASH(write_info, u64, struct val_t);
BPF_HASH(rettmp, u64, struct tmp_t);
BPF_HASH(fdtmp, u64, struct tmp_t);

int entry_vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    struct val_t val = {};
    struct tmp_t *fdp, *retp;
    struct task_struct *tp;
    struct file *fp;
    u64 id = bpf_get_current_pid_tgid();
    u32 self = id >> 32;
    if (self == %d) return 0;
 
    u64 ts = bpf_ktime_get_ns();

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0)
    {
        val.pid = id >> 32;
        val.uid = bpf_get_current_uid_gid();
        tp = (struct task_struct*)bpf_get_current_task();
        val.pr = tp->prio;
        //fp = (struct file *)PT_REGS_PARM1(ctx);
        bpf_probe_read_kernel_str(val.fstype, sizeof(val.fstype), file->f_inode->i_sb->s_type->name);

        fdp = fdtmp.lookup(&id);
        if (fdp == 0)
            return 0;
        else
        {
            val.fd = fdp->fd;
        }

        retp = rettmp.lookup(&id);
        if (retp == 0)
            return 0;
        else
        {
            val.ret = retp->ret;
        }

        write_info.update(&ts, &val);
    }

    return 0;
}

int entry_ksys_write(struct pt_regs *ctx, unsigned int fd, const char __user *buf, size_t count)
{
    struct tmp_t tmp= {};
    u64 id = bpf_get_current_pid_tgid(); 
    u32 self = id >> 32;
    if (self == %d) return 0;

    int fdt = fd;
    if (fdt >= 0)
        tmp.fd = fdt;
    else
        tmp.fd= -1;
    
    fdtmp.update(&id, &tmp);

    return 0;
}

int exit_vfs_write(struct pt_regs *ctx)
{
    struct tmp_t tmp= {};
    u64 id = bpf_get_current_pid_tgid(); 
    u32 self = id >> 32;
    if (self == %d) return 0;

    ssize_t ret = PT_REGS_RC(ctx);
    tmp.ret = ret;
    
    rettmp.update(&id, &tmp);

    return 0;
}
""" % (self,self,self)

b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_write", fn_name="entry_vfs_write")
b.attach_kprobe(event="ksys_write", fn_name="entry_ksys_write")
b.attach_kretprobe(event="vfs_write",fn_name="exit_vfs_write")

write_info = b.get_table("write_info")

def print_info():
    title()
    while True:
        try:
            sleep(interval)
            for k, v in sorted(write_info.items(), key=lambda write_info:write_info[0].value):
                print("%-16d" % k.value ,end="")
                print("pid=%-8d" % v.pid, end="")
                print("comm=%-8s" % v.comm, end="")
                print("pr=%-6d" % v.pr, end="")
                print("user=%-6s" % pwd.getpwuid(v.uid)[0], end="")
                print("fd=%-5d" % v.fd, end="")
                if(len(v.fstype)==0):
                    print("NULL", end="")
                else:
                    print("fs=%-8s " % v.fstype.decode(), end="")
                print("ret=%-5d" % v.ret, end="")
                print()
            print()
            b['write_info'].clear()
            b['fdtmp'].clear()
            b['rettmp'].clear()
            
        except KeyboardInterrupt:
            pass
            exit()
    
def print_count():
    title()
    dic = {}

    while True:
        sleep(interval)
        for k, v in sorted(write_info.items(), key=lambda write_info:write_info[0].value):
            str = "pid=%-8d comm=%-8s pr=%-6d user=%-6s fd=%-5d fs=%-8s ret=%-5d" % \
            (v.pid, v.comm, v.pr, pwd.getpwuid(v.uid)[0], v.fd, v.fstype, v.ret)
            if dic.get(str,-1) == -1:
                dic[str]=1
            else:
                dic[str]+=1

        i = 0
        print("TIME:%-10s" % strftime("%H:%M:%S"))
        for k, v in sorted(dic.items(), key=lambda item:item[1], reverse=True):
            i += 1
            print("NO.%-4d" % (i), end="")
            print("%-4d%s" % (v, k))
            if i==10:
                break
        dic = {}

        b['write_info'].clear()
        b['fdtmp'].clear()
        b['rettmp'].clear()


if args.count:
    print_count()
else:
    print_info()
      
