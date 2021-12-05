#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @lint-avoid-python-3-compatibility-imports
#
# runqlen    Summarize scheduler run queue length as a histogram.
#            For Linux, uses BCC, eBPF.
#
# This counts the length of the run queue, excluding the currently running
# thread, and shows it as a histogram.
#
# Also answers run queue occupancy.
#
# USAGE: runqlen [-h] [-T] [-Q] [-m] [-D] [interval] [count]
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support). Under tools/old is
# a version of this tool that may work on Linux 4.6 - 4.8.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Dec-2016   Brendan Gregg   Created this.
# 17-Sep-2020   Chenyu Zhao     Edited

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from time import sleep, strftime
from tempfile import NamedTemporaryFile
from os import open, close, dup, unlink, O_WRONLY
# for influxdb
import sys
sys.path.append('./plugins/common/')
from const import DatabaseType
from init_db import influx_client
from db_modules import write2db

# connect to influxdb

frequency = 20
interval = 99999999

# init BPF program
b = BPF(src_file="runqlen.c")
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
    sample_period=0, sample_freq=frequency)

# dist = b.get_table("dist")

# data structure from template
class lmp_data(object):
    def __init__(self,a,b):
            self.glob = a
            self.runqlen = b

data_struct = {"measurement":'runqlenTable',
                "tags":['glob'],
                "fields":['runqlen']}

def print_event(cpu, data, size):
    global start
    event = b["result"].event(data)
    test_data = lmp_data('glob', event.len)
    write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
    # print(event.len)
    # if start == 0:
    #         start = event.ts
    # time_s = (float(event.ts - start)) / 1000000000
    # print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
    #     "Hello, perf_output!"))

b["result"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()
    try:
        pass
    except KeyboardInterrupt:
        exit()