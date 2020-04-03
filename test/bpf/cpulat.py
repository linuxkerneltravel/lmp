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



# from tempfile import NamedTemporaryFile
from os import open, close, dup, unlink, O_WRONLY

# import asyncio

frequency = 99

b = BPF(src_file='bpf-cpulat.c')
b.attach_kprobe(event="ttwu_do_wakeup", fn_name="trace_ttwu_do_wakeup")
b.attach_kprobe(event="wake_up_new_task", fn_name="trace_wake_up_new_task")
b.attach_kprobe(event="finish_task_switch", fn_name="trace")
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
    sample_period=0, sample_freq=frequency)
b.attach_kprobe(event="handle_irq_event_percpu", fn_name="trace_start")
b.attach_kretprobe(event="handle_irq_event_percpu",
    fn_name="trace_completion")





print("start... Hit Ctrl-C to end.")


def print_event(cpu, data, size):
    global start
    event = b["result"].event(data)
    # 输出数据
    # f.write(strftime("%H:%M:%S") + " " + str(event.time) + '\r\n')
    # print("%-8s\n" % strftime("%H:%M:%S"))
    print(event.total_latency_time, event.total_len, event.total_oncpu_time, event.total_softirq, event.total_hardirq)


exiting = 0 
# f = open("/home/zcy/my_bcc/my_data/cpu-runqlat/data.csv",'w')
b["result"].open_perf_buffer(print_event)
while 1:
	try:
		b.perf_buffer_poll()
	except KeyboardInterrupt:
		exiting = 1
	if exiting == 1:
		# f.close()
		exit()
	









