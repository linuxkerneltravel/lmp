#!/usr/bin/python
# monitoring readahead
#
# Print processes and PID which call write method and ordered by counts 
# 
# Based on readahead.py(bcc)
# Copyright (c) 2020 Suchakra Sharma <mail@suchakra.in>
# Licensed under the Apache License, Version 2.0 (the "License")
# This was originally created for the BPF Performance Tools book
# published by Addison Wesley. ISBN-13: 9780136554820
# When copying or porting, include this comment.
#
# version 1.0

from __future__ import print_function
from bcc import BPF
from time import sleep,strftime
import ctypes as c_int
import argparse
import os
import pwd

# Print interval
interval = 5
print("Print readahead info every %ds" % interval)
print("------------------------------")

# parser = argparse.ArgumentParser(
#     description="Trace readahead",
#     formatter_class=argparse.RawDescriptionHelpFormatter,
#     epilog=examples)
# parser.add_argument("-t", "--time", action="store_true",
#     help="show processing time of readahead")
# parser.add_argument("-c", "--count", action="store_true",
#     help="show counts during a period time")
# parser.add_argument("-d", "--detail", action="store_true",
#     help="show detail information")
# parser.add_argument("-p", "--pid", action="store_true",
#     help="trace this PID only")
# args = parser.parse_args()


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

# define PAGE_COUNT     1
# define ENTER_RA       2
# define EXIT_RA        3

struct data_t
{
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 uid;
    u64 ts;
};

BPF_HASH(flags, u64, int); 
//BPF_HASH(count, u64, u64);             // used to count num of single pid's appearance
BPF_HASH(info, u64, struct data_t);    // used to track if in do_page_cache_readahead()
BPF_HASH(birth, struct page*, u64);
BPF_ARRAY(pages); 
BPF_HASH(delta, u64, u64); 

int entry_readahead(struct pt_regs *ctx)
{
    struct data_t data = {};

    u64 id = bpf_get_current_pid_tgid();
//    count.atomic_increment(id);

    u32 pid = id >> 32;
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.uid = bpf_get_current_uid_gid();
    data.ts = bpf_ktime_get_ns();
    info.update(&id, &data);
    
    int flag = ENTER_RA;
    flags.update(&id, &flag);

    return 0;
}

int exit_readahead(struct pt_regs *ctx)
{
    struct data_t data = {};

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.uid = bpf_get_current_uid_gid();
    data.ts = bpf_ktime_get_ns();
    info.update(&id, &data);
    
    int flag = EXIT_RA;
    flags.update(&id, &flag);

    return 0;
}

int exit_page_cache_alloc(struct pt_regs *ctx)
{
    int key = PAGE_COUNT;
    u64 id = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    struct page *retval = (struct page*)PT_REGS_RC(ctx);

    int *f = flags.lookup(&id);
    if (f != NULL && *f == ENTER_RA) {
        pages.atomic_increment(key);
        birth.update(&retval, &ts);
    }
    return 0;
}

int entry_mark_page_accessed(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    struct page *arg0 = (struct page *)PT_REGS_PARM1(ctx);  

    u64 *bts = birth.lookup(&arg0);
    if (bts != NULL) {
        int key = PAGE_COUNT;
        u64 dt = ts - *bts;
        pages.atomic_increment(key, -1);
        delta.atomic_increment(dt);
    }
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="ondemand_readahead", fn_name="entry_readahead")
b.attach_kretprobe(event="ondemand_readahead", fn_name="exit_readahead")
b.attach_kretprobe(event="__page_cache_alloc", fn_name="exit_page_cache_alloc")
b.attach_kprobe(event="mark_page_accessed", fn_name="entry_mark_page_accessed")

delta = b.get_table("delta")
info = b.get_table("info")

def print_info():
    i = 0
    dic = {}
    print("TIME: %-8s " % strftime("%H:%M:%S"))
    print("Read-ahead unused pages: %d" % (b["pages"][c_int.c_ulong(0)].value))
    
    print("Cost time(get page->mark acessed) and num - %d items" % len(delta))
    for k, v in sorted(delta.items(), key=lambda delta:delta[0].value, reverse=True):
        print("%d(ms):" % k.value, end="")
        print("%d   " % v.value, end="")
    print()
    delta.clear()

    print("Do_read-ahead info:")
    for k, v in sorted(info.items(), key=lambda info:info[0].value, reverse=True):
        str = "pid=%d user=%s[%d] comm=%s " % \
              (v.pid, (pwd.getpwuid(v.uid)[0]), v.uid, v.comm)
        if dic.get(str,-1) == -1:
            dic[str]=1
        else:
            dic[str]+=1
    for k, v in sorted(dic.items(), key=lambda item:item[1], reverse=True):
        i += 1
        print("%d:   " % (i), end="")
        print("Count=%d %-4s" % (v, k))
    dic = {}
    info.clear()

    print()
    b['flags'].clear()
    b['birth'].clear()
    b['pages'].clear()

while True:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        pass
        exit()

    print_info()


# args = parser.parse_args()
# if args.time:
#     print("Trace processing time... Hit Ctrl-C to end and print.")
#     exit()

# if args.count:
#     print("Trace count of readahead... Hit Ctrl-C to end and print.")
#     exit()
    
# if args.detail:
#     print("Trace detail information... Hit Ctrl-C to end and print.")
#     exit()

# if args.pid:
#     print("Trace process %d... Hit Ctrl-C to end and print." %  args.pid)
#     exit()
    
# else:
#     print(examples)
#     exit()











