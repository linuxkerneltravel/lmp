#!/usr/bin/python
# monitoring open syscall
#
# Print processes and PID which call open method and ordered by counts 
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
    ./open          # trace file open info
    ./open -c       # trace TOP10 info
"""
parser = argparse.ArgumentParser(
    description="Trace file open info",
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
    print("Print file open info" )
    print("'-c' to show TOP10 info every %ds ordered by counts." % interval)
    print("---------------------------------------------------")
    sleep(2)

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/openat2.h>
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
    u64 flags; 
    int fd;
    char fstype[FNAME_MAX];
    char fname[256];
};

struct fs_t {
    int fd;
    char fstype[FNAME_MAX];
};


BPF_HASH(open_info, u64, struct val_t);
BPF_HASH(fstmp, u64, struct fs_t);
BPF_HASH(fdtmp, u64, struct fs_t);

int entry_do_sys_openat2(struct pt_regs *ctx, int dfd, const char __user *filename, struct open_how *how)
{
    struct val_t val = {};
    struct fs_t *fsp;
    struct fs_t *fdp;
    struct task_struct *tp;
    u64 id = bpf_get_current_pid_tgid();
    u32 self = id >> 32;
    if (self == %d) return 0;
 
    u64 ts = bpf_ktime_get_ns();

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0)
    {
        val.pid = id >> 32;
        val.uid = bpf_get_current_uid_gid();
        val.flags = how->flags;
        bpf_probe_read_user_str(val.fname, sizeof(val.fname), filename);
        tp = (struct task_struct*)bpf_get_current_task();
        val.pr = tp->prio;

        fdp = fdtmp.lookup(&id);
        if (fdp == 0)
            return 0;
        else
        {
            val.fd = fdp->fd;
        }

        fsp = fstmp.lookup(&id);
        if (fsp == 0)
            return 0;
        else
        {
            bpf_probe_read_kernel_str(val.fstype, sizeof(val.fstype), fsp->fstype);
        }
        open_info.update(&ts, &val);
    }

    return 0;
}

int exit_do_sys_openat2(struct pt_regs *ctx)
{
    struct fs_t fs= {};
    u64 id = bpf_get_current_pid_tgid(); 
    u32 self = id >> 32;
    if (self == %d) return 0;

    int fd = PT_REGS_RC(ctx);
    if (fd >= 0)
        fs.fd = fd;
    else
        fs.fd= -1;
    
    fdtmp.update(&id, &fs);

    return 0;
}

int exit_do_filp_open(struct pt_regs *ctx)
{
    struct fs_t fs= {};
    u64 id = bpf_get_current_pid_tgid(); 
    u32 self = id >> 32;
    if (self == %d) return 0;

    struct file *fp = (struct file *)PT_REGS_RC(ctx);
    bpf_probe_read_kernel_str(fs.fstype, sizeof(fs.fstype), fp->f_inode->i_sb->s_type->name);
    
    fstmp.update(&id, &fs);

    return 0;
}
""" % (self,self,self)

b = BPF(text=bpf_text)
b.attach_kprobe(event="do_sys_openat2", fn_name="entry_do_sys_openat2")
b.attach_kretprobe(event="do_sys_openat2",fn_name="exit_do_sys_openat2")
b.attach_kretprobe(event="do_filp_open",fn_name="exit_do_filp_open")

fstmp = b.get_table("fstmp")
open_info = b.get_table("open_info")

def print_info():
    title()
    while True:
        try:
            sleep(interval)
            for k, v in sorted(open_info.items(), key=lambda open_info:open_info[0].value):
                print("%-16d" % k.value ,end="")
                print("pid=%-8d" % v.pid, end="")
                print("comm=%-8s" % v.comm, end="")
                print("pr=%-6d" % v.pr, end="")
                print("user=%-6s" % pwd.getpwuid(v.uid)[0], end="")
                print("fd=%-5d" % v.fd, end="")
                print("flag=%08o  " % v.flags, end="")
                print("fs=%-8s" % v.fstype.decode(), end="")
                print("path=%-18s" % v.fname.decode(), end="")
                print()
            print()
            b['open_info'].clear()
            b['fdtmp'].clear()
            b['fstmp'].clear()

        except KeyboardInterrupt:
            pass
            exit()
    
def print_count():
    title()
    dic = {}

    while True:
        sleep(interval)
        for k, v in sorted(open_info.items(), key=lambda open_info:open_info[0].value):
            str = "pid=%-8d comm=%-8s pr=%-6d user=%-6s fd=%-5d flag=%08o fs=%-8s path=%-18s" % \
            (v.pid, v.comm, v.pr, pwd.getpwuid(v.uid)[0], v.fd, v.flags, v.fstype, v.fname)
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

        b['open_info'].clear()
        b['fdtmp'].clear()
        b['fstmp'].clear()


if args.count:
    print_count()
else:
    print_info()
      
