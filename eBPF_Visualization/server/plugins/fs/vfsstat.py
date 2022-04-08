#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @lint-avoid-python-3-compatibility-imports
#
# vfsstat.py   Count some VFS calls.
#           For Linux, uses BCC, eBPF. See .c file.
#
# Written as a basic example of counting multiple events as a stat tool.
#
# USAGE: vfsstat.py [interval [count]]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Aug-2015   Brendan Gregg   Created this.
# 15-Sep-2020   Chenyu Zhao     Edited

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime
from sys import argv

import sys
sys.path.append('./plugins/common/')
from const import DatabaseType
from init_db import influx_client
from db_modules import write2db

def usage():
    print("USAGE: %s [interval [count]]" % argv[0])
    exit()

interval = 1
count = -1

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

enum stat_types {
    S_READ = 1,
    S_WRITE,
    S_FSYNC,
    S_OPEN,
    S_CREATE,
    S_MAXSTAT
};

BPF_ARRAY(stats, u64, S_MAXSTAT);

static void stats_increment(int key) {
    u64 *leaf = stats.lookup(&key);
    if (leaf) (*leaf)++;
}

void do_read(struct pt_regs *ctx) { stats_increment(S_READ); }
void do_write(struct pt_regs *ctx) { stats_increment(S_WRITE); }
void do_fsync(struct pt_regs *ctx) { stats_increment(S_FSYNC); }
void do_open(struct pt_regs *ctx) { stats_increment(S_OPEN); }
void do_create(struct pt_regs *ctx) { stats_increment(S_CREATE); }

""")
b.attach_kprobe(event="vfs_read", fn_name="do_read")
b.attach_kprobe(event="vfs_write", fn_name="do_write")
b.attach_kprobe(event="vfs_fsync", fn_name="do_fsync")
b.attach_kprobe(event="vfs_open", fn_name="do_open")
b.attach_kprobe(event="vfs_create", fn_name="do_create")


data_struct = {"measurement":'vfsstatTable',
                "tags":['glob'],
                "fields":['total_read','total_write','total_create','total_open','total_fsync']}

class test_data(object):
    def __init__(self,a,b,c,d,e,f):
            self.glob = a
            self.total_read = b
            self.total_write = c
            self.total_fsync = d
            self.total_open = e
            self.total_create = f


# stat column labels and indexes
stat_types = {
    "READ": 1,
    "WRITE": 2,
    "FSYNC": 3,
    "OPEN": 4,
    "CREATE": 5
}

# output
i = 0
while (1):
    if count > 0:
        i += 1
        if i > count:
            exit()
    try:
        sleep(interval)
    except KeyboardInterrupt:
        pass
        exit()

    

    # print("%-8s: " % strftime("%H:%M:%S"), end="")
    # print each statistic as a column
    vfs_list = [0,0,0,0,0,0]
    times=1
    for stype in stat_types.keys():
        idx = stat_types[stype]
        # print(idx)
        try:
            val = b["stats"][c_int(idx)].value / interval
        except:
            val = 0
        vfs_list[times] = val
        times += 1
        if times == 5:
            times=0
    # print(vfs_list[1],vfs_list[2],vfs_list[3],vfs_list[4],vfs_list[5])
    data = test_data('glob', vfs_list[1],vfs_list[2],vfs_list[3],vfs_list[4],vfs_list[5])
    write2db(data_struct, data, influx_client, DatabaseType.INFLUXDB.value)

    b["stats"].clear()
