#!/usr/bin/python
# -*- coding: utf-8 -*-
# @lint-avoid-python-3-compatibility-imports
#
# runqlat   Run queue (scheduler) latency as a histogram.
#           For Linux, uses BCC, eBPF.
#
# USAGE: runqlat [-h] [-T] [-m] [-P] [-L] [-p PID] [interval] [count]
#
# This measures the time a task spends waiting on a run queue for a turn
# on-CPU, and shows this time as a histogram. This time should be small, but a
# task may need to wait its turn due to CPU load.
#
# This measures two types of run queue latency:
# 1. The time from a task being enqueued on a run queue to its context switch
#    and execution. This traces ttwu_do_wakeup(), wake_up_new_task() ->
#    finish_task_switch() with either raw tracepoints (if supported) or kprobes
#    and instruments the run queue latency after a voluntary context switch.
# 2. The time from when a task was involuntary context switched and still
#    in the runnable state, to when it next executed. This is instrumented
#    from finish_task_switch() alone.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from time import sleep, strftime
import argparse
from prometheus_client import Gauge,start_http_server


# from tempfile import NamedTemporaryFile
import os


# 定义命令行参数
parser = argparse.ArgumentParser(
    description="Extraction the data of the task_struct",)

parser.add_argument("-P", "--pid", help="the process's pid")

args = parser.parse_args()
print(args.pid)


fp = open('/usr/libexec/lmp/collector/bpf.c','w')
lines = open('/usr/libexec/lmp/collector/collect.c').readlines()
for s in lines:
    fp.write(s.replace('PID',args.pid))
fp.close()


frequency = 99

b = BPF(src_file='/usr/libexec/lmp/collector/bpf.c')
# b = BPF(text = file_data)
b.attach_kprobe(event="ttwu_do_wakeup", fn_name="trace_ttwu_do_wakeup")
b.attach_kprobe(event="wake_up_new_task", fn_name="trace_wake_up_new_task")
b.attach_kprobe(event="finish_task_switch", fn_name="trace")
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
    sample_period=0, sample_freq=frequency)
b.attach_kprobe(event="handle_irq_event_percpu", fn_name="trace_start")
b.attach_kretprobe(event="handle_irq_event_percpu",
    fn_name="trace_completion")
# 用于统计文件系统的信息
b.attach_kprobe(event="vfs_read", fn_name="do_read")
b.attach_kprobe(event="vfs_write", fn_name="do_write")
b.attach_kprobe(event="vfs_fsync", fn_name="do_fsync")
b.attach_kprobe(event="vfs_open", fn_name="do_open")
b.attach_kprobe(event="vfs_create", fn_name="do_create")
# 用于统计页缓存
b.attach_kprobe(event="add_to_page_cache_lru", fn_name="do_count_apcl")
b.attach_kprobe(event="mark_page_accessed", fn_name="do_count_mpa")
b.attach_kprobe(event="account_page_dirtied", fn_name="do_count_apd")
b.attach_kprobe(event="mark_buffer_dirty", fn_name="do_count_mbd")


latency_time = Gauge('total_latency_time', 'latency time ',['host'])
length = Gauge('total_len', 'the length of runqueue',['host'])
oncpu_time = Gauge('total_oncpu_time', 'the on-CPU time of PID',['host'])
softirq = Gauge('total_softirq', 'the softirq time',['host'])
hardirq = Gauge('total_hardirq', 'the hardirq time',['host'])
read_t = Gauge('total_read_t', 'the read_t times',['host'])
write_t = Gauge('total_write_t', 'the write_t times',['host'])
fsync_t = Gauge('total_fsync_t', 'the fsync_t times',['host'])
open_t = Gauge('total_open_t', 'the open_t times',['host'])
create_t = Gauge('total_create_t', 'the create_t times',['host'])


print("start... Hit Ctrl-C to end.")


def print_event(cpu, data, size):
    global start
    event = b["result"].event(data)
    # 输出数据
    # f.write(strftime("%H:%M:%S") + " " + str(event.time) + '\r\n')
    # print("%-8s\n" % strftime("%H:%M:%S"))
    # mpa是统计缓存访问的次数
    # mbd是统计缓存的写入
    # apcl统计的是页面添加数量
    # apd统计的是脏页面数量
    total = max(0,event.mpa) - max(0,event.mbd)
    misses = max(0,event.apcl) - max(0,event.apd)
    if misses < 0:
        misses = 0
    if total < 0:
        total = 0
    hits = total - misses
    if hits < 0:
        misses = total
        hits = 0
    ratio = 0
    if total > 0:
        ratio = float(hits) / total

    latency_time.labels(host="a").set(event.total_latency_time)
    length.labels(host="a").set(event.total_len)
    oncpu_time.labels(host="a").set(event.total_oncpu_time)
    softirq.labels(host="a").set(event.total_softirq)
    hardirq.labels(host="a").set(event.total_hardirq)
    read_t.labels(host="a").set(event.total_read)
    write_t.labels(host="a").set(event.total_write)
    fsync_t.labels(host="a").set(event.total_fsync)
    open_t.labels(host="a").set(event.total_open)
    create_t.labels(host="a").set(event.total_create)
    b["stats"].clear()
    b["cachestat"].clear()

exiting = 0 
# f = open("/home/zcy/my_bcc/my_data/cpu-runqlat/data.csv",'w')
if __name__ == '__main__':
    start_http_server(8002)           #8002端口启动
    b["result"].open_perf_buffer(print_event)
    while 1:
    	try:
    		b.perf_buffer_poll()
    	except KeyboardInterrupt:
    		exiting = 1
    	if exiting == 1:
    		# f.close()
    		exit()
	









