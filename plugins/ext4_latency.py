#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ext4dist  Summarize ext4 operation latency.
#           For Linux, uses BCC, eBPF.
#
# USAGE: ext4dist [-h] [-T] [-m] [-p PID] [interval] [count]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Feb-2016   Brendan Gregg   Created this.
from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
# for influxdb
from influxdb import InfluxDBClient
import lmp_influxdb as db
from db_modules import write2db

from datetime import datetime

DBNAME = 'lmp'

client = db.connect(DBNAME,user='root',passwd=123456)

# symbols
kallsyms = "/proc/kallsyms"
# arguments
examples = """examples:
    ./ext4dist -p 181     # trace PID 181 only
    ./ext4dist 1 10       # print 1 second summaries, 10 times
    ./ext4dist 5       # 5s summaries, milliseconds
"""
parser = argparse.ArgumentParser(
    description="Summarize ext4 operation latency",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--notimestamp", action="store_true",
                    help="don't include timestamp on interval output")
parser.add_argument("-m", "--milliseconds", action="store_true",
                    help="output in milliseconds")
parser.add_argument("-p", "--pid",
                    help="trace this PID only")
parser.add_argument("interval", nargs="?",
                    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
                    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()
pid = args.pid
countdown = int(args.count)
# if args.milliseconds:
#     factor = 1000000
#     label = "msecs"
# else:
#     factor = 1000
#     label = "usecs"
if args.interval and int(args.interval) == 0:
    interval = 1
else:
    interval =  args.interval
    
debug = 0
# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/uio.h>
#define OP_NAME_LEN 8
typedef struct key_s {
    u32 pid;
    u32 flag;
    u64 ts;
} key_s;
typedef struct val_t  {
    char op[OP_NAME_LEN];
    char comm[TASK_COMM_LEN];
    char flags;
    u64 delta;
} val_t ;
//record start time
BPF_HASH(start, u32,key_s);
//output to userspace
BPF_HASH(dist,  key_s, val_t );
// time operation
int trace_entry(struct pt_regs *ctx,struct kiocb *iocb,struct iov_iter *from)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (FILTER_PID)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    struct file *fp = iocb->ki_filp;
     key_s key = {
     .pid = pid,
     .flag = fp->f_flags,
     .ts = ts,
     };
    start.update(&pid, &key);
    return 0;
}
// old version
EXT4_TRACE_READ_CODE
static int trace_return(struct pt_regs *ctx, const char *op)
{
    key_s *key;
    val_t *valp, zero = {};
    u32 pid = bpf_get_current_pid_tgid();
    // fetch timestamp and calculate delta
    key = start.lookup(&pid);
    if (!key || key->pid != pid) {
        return 0;   // missed start or filtered
    }
    //calculate delta
    u64 delta = bpf_ktime_get_ns() - key->ts;
    // Skip entries with backwards time: temp workaround for #728
    if ((s64) delta < 0)
        return 0;
    //delta /= FACTOR;
    // store as histogram
    valp = dist.lookup_or_try_init(key, &zero);
     if (valp){
            valp->delta = delta;
            bpf_get_current_comm(valp->comm, sizeof(valp->comm));
            __builtin_memcpy(valp->op, op, sizeof(valp->op));
    }
    start.delete(&pid);
    return 0;
}
int trace_read_return(struct pt_regs *ctx)
{
    char *op = "read";
    return trace_return(ctx, op);
}
int trace_write_return(struct pt_regs *ctx)
{
    char *op = "write";
    return trace_return(ctx, op);
}

int trace_open_return(struct pt_regs *ctx)
{
    char *op = "open";
    return trace_return(ctx, op);
}
int trace_fsync_return(struct pt_regs *ctx)
{
    char *op = "fsync";
    return trace_return(ctx, op);
}

"""
# Starting from Linux 4.10 ext4_file_operations.read_iter has been changed from
# using generic_file_read_iter() to its own ext4_file_read_iter().
#
# To detect the proper function to trace check if ext4_file_read_iter() is
# defined in /proc/kallsyms, if it's defined attach to that function, otherwise
# use generic_file_read_iter() and inside the trace hook filter on ext4 read
# events (checking if file->f_op == ext4_file_operations).
if BPF.get_kprobe_functions(b'ext4_file_read_iter'):
    ext4_read_fn = 'ext4_file_read_iter'
    ext4_trace_read_fn = 'trace_entry'
    ext4_trace_read_code = ''
else:
    ext4_read_fn = 'generic_file_read_iter'
    ext4_trace_read_fn = 'trace_read_entry'
    ext4_file_ops_addr = ''
    with open(kallsyms) as syms:
        for line in syms:
            (addr, size, name) = line.rstrip().split(" ", 2)
            name = name.split("\t")[0]
            if name == "ext4_file_operations":
                ext4_file_ops_addr = "0x" + addr
                break
        if ext4_file_ops_addr == '':
            print("ERROR: no ext4_file_operations in /proc/kallsyms. Exiting.")
            print("HINT: the kernel should be built with CONFIG_KALLSYMS_ALL.")
            exit()
    ext4_trace_read_code = """
int trace_read_entry(struct pt_regs *ctx, struct kiocb *iocb)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (FILTER_PID)
        return 0;
    // ext4 filter on file->f_op == ext4_file_operations
    struct file *fp = iocb->ki_filp;
    if ((u64)fp->f_op != %s)
        return 0;
    u64 ts = bpf_ktime_get_ns();
     key_s key = {
     .pid = pid,
     .flag = fp->f_flags,
     .ts = ts
     };
    start.update(&pid, &key);
    return 0;
}""" % ext4_file_ops_addr
# code replacements
bpf_text = bpf_text.replace('EXT4_TRACE_READ_CODE', ext4_trace_read_code)
# bpf_text = bpf_text.replace('FACTOR', str(factor))
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()
# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event=ext4_read_fn, fn_name=ext4_trace_read_fn)
b.attach_kprobe(event="ext4_file_write_iter", fn_name="trace_entry")
b.attach_kprobe(event="ext4_file_open", fn_name="trace_entry")
b.attach_kprobe(event="ext4_sync_file", fn_name="trace_entry")
b.attach_kretprobe(event=ext4_read_fn, fn_name='trace_read_return')
b.attach_kretprobe(event="ext4_file_write_iter", fn_name="trace_write_return")
b.attach_kretprobe(event="ext4_file_open", fn_name="trace_open_return")
b.attach_kretprobe(event="ext4_sync_file", fn_name="trace_fsync_return")


data_struct = {"measurement":'ext4LatencyTable',
                "time":[],
                "tags":['glob'],
                "fields":['comm','pid','operate','latency']}

class lmp_data(object):
    def __init__(self,a,b,c,d,e,f):
            self.glob = a
            self.comm = b
            self.pid = c
            self.operate = d
            self.latency = e
            self.time = f



# print("Tracing ext4 operation latency... Hit Ctrl-C to end.")
# print("%-16s %-6s %-8s %s" % ("COMM", "PID","OP", "LAT(ms)"))
# output
exiting = 0
while (1):
    try:
        if args.interval:
            sleep(int(args.interval))
        else:
            sleep(5)
    except KeyboardInterrupt:
        exiting = 1
    dist = b.get_table("dist")
    # print("The number counted in %d seconds is: %d" %(int(args.interval),dist.__len__()))
    # print()
    sum =0;
    for k,v in dist.items():
        delay = float(v.delta)/1000000
        # print("%-16s %-6d %-8s %f" % (v.comm.decode('utf-8', 'replace'),k.pid,v.op.decode('utf-8', 'replace'),delay))
        test_data = lmp_data('glob',v.comm.decode('utf-8', 'replace'),k.pid,v.op.decode('utf-8', 'replace'),delay,datetime.now().isoformat())
        write2db(data_struct, test_data, client)
    # print()
    dist.clear()
    countdown -= 1
    if exiting or countdown == 0:
        exit()