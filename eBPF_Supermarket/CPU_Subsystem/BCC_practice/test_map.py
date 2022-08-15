#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from bcc.utils import printb
import time
from bpfutil import printList

startTime = time.time()
frequency = 49

# load BPF program
bpf = BPF(src_file="map.c")
bpf.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_sched_switch")
bpf.attach_tracepoint(tp="irq:softirq_entry", fn_name="trace_softirq_entry")
bpf.attach_tracepoint(tp="irq:softirq_exit", fn_name="trace_softirq_exit")
bpf.attach_tracepoint(tp="sched:sched_process_fork", fn_name="trace_sched_process_fork")
bpf.attach_kprobe(event="update_rq_clock", fn_name="update_rq_clock")
bpf.attach_tracepoint(tp="irq:irq_handler_entry", fn_name="trace_irq_handler_entry")
bpf.attach_tracepoint(tp="irq:irq_handler_exit", fn_name="trace_irq_handler_exit")

# 传递给bpf程序的定时事件
bpf.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="tick_update",
    sample_period=0, sample_freq=frequency)

print("Tracing for Data's... Ctrl-C to end")

timeStr = time.strftime("%H:%M:%S")
print("%s proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms"
        % timeStr)

# 长期保存的数值
proc = 0
cswch = 0
irqTime = 0
softTime = 0
idleTime = 0
actualTime = 0

# 测试idlePidList的功能
# while 1:
#     printList(bpf['idlePid'])
#     time.sleep(2)

while 1:
    # 上下文切换数
    # bpf['countMap'][0] 的类型是 ctypes.c_ulong，要得到其值需要.value
    cswch_s = bpf["countMap"][0].value
    cswch_s, cswch = cswch_s - cswch, cswch_s

    # 每秒新建进程数(fork)
    proc_s = bpf["countMap"][1].value
    proc_s, proc = proc_s - proc, proc_s

    # 运行队列长度
    runqlen_list = bpf['runqlen'][0]
    runqlen = 0
    for i in runqlen_list:
        runqlen += i

    # irq占用时间
    _irqTime = irqTime
    irqTime = bpf["irqLastTime"][0].value
    dtaIrq = (irqTime - _irqTime) / 1000 # 多个CPU的irq时间总和，单位us

    # irq占用时间
    _softTime = softTime
    softTime = bpf["softirqLastTime"][0].value
    dtaSoft = (softTime - _softTime) / 1000 # 多个CPU的softirq时间总和，单位us

    # IDLE时间
    _idleTime = idleTime
    idleTime = bpf['idleLastTime'][0].value
    dtaIdle = (idleTime - _idleTime) / 1000 # ms

    timeStr = time.strftime("%H:%M:%S")
    print("%s %6d  %7d  %7d  %10d  %10d  %7d" %
        (timeStr, proc_s, cswch_s, runqlen, dtaIrq, dtaSoft, dtaIdle) )

    time.sleep(1)
    # bpf.trace_print()