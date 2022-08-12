#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from bcc.utils import printb
import time
from bpfutil import printList
import ctypes

startTime = time.time()
frequency = 49

# load BPF program
bpf = BPF(src_file="sar.c")
bpf.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_sched_switch")
bpf.attach_tracepoint(tp="irq:softirq_entry", fn_name="trace_softirq_entry")
bpf.attach_tracepoint(tp="irq:softirq_exit", fn_name="trace_softirq_exit")
bpf.attach_tracepoint(tp="sched:sched_process_fork", fn_name="trace_sched_process_fork")
bpf.attach_kprobe(event="update_rq_clock", fn_name="update_rq_clock")
bpf.attach_tracepoint(tp="irq:irq_handler_entry", fn_name="trace_irq_handler_entry")
bpf.attach_tracepoint(tp="irq:irq_handler_exit", fn_name="trace_irq_handler_exit")
bpf.attach_tracepoint(tp="power:cpu_idle", fn_name="trace_cpu_idle")

bpf.attach_tracepoint(tp="raw_syscalls:sys_enter", fn_name="trace_sys_enter")
bpf.attach_tracepoint(tp="raw_syscalls:sys_exit", fn_name="trace_sys_exit")

# 上下文切换完成后的函数，包含了当前进程的ts和过去进程的ts
bpf.attach_kprobe(event_re="^finish_task_switch$|^finish_task_switch\.isra\.\d$",
                fn_name="finish_sched")

# 传递给bpf程序的定时事件
bpf.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="tick_update",
    sample_period=0, sample_freq=frequency)

print("Search kernel Symbols in /proc/kallsyms")
# 找runqueues会找到以下两种，所以需要限制尾部严格相同
# b'0000000000034e80 A runqueues\n'
# b'ffffffff8230b040 t sync_runqueues_membarrier_state\n'
addr = 0
ksym = "total_forks"
with open("/proc/kallsyms", 'r') as f:
    line = f.readline()
    while line:
        if line[:-1].endswith(ksym):
            addr = line.split(" ")[0]
            break
        line = f.readline()

bpf['symAddr'][0] = ctypes.c_longlong(int(addr, base=16))

print("Tracing for Data's... Ctrl-C to end")
thead_str = "  time   proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms"
print(thead_str)

# 长期保存的数值
proc = 0
cswch = 0
irqTime = 0
softTime = 0
idleTime = 0
actualTime = 0
ktLastTime = 0
syscTime = 0
utLastTime = 0

line = 0

# 测试idlePidList的功能
# while 1:
#     printList(bpf['idlePid'])
#     time.sleep(2)

while 1:
    time.sleep(1)
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
    dtaIdle = (idleTime - _idleTime) / 1000000 # ms

    # kthread运行时间
    _ktLastTime = ktLastTime
    ktLastTime = bpf['ktLastTime'][0].value
    dtaKT = (ktLastTime - _ktLastTime) / 1000 # us

    # syscall占用时间
    _syscTime = syscTime
    syscTime = bpf['syscTime'][0].value
    dtaSysc = (syscTime - _syscTime) / 1000000

    # userThread占用时间
    _utLastTime = utLastTime
    utLastTime = bpf['utLastTime'][0].value
    dtaUTime = utLastTime - _utLastTime
    dtaUTime = (dtaUTime - (syscTime - _syscTime)) / 1000000

    timeStr = time.strftime("%H:%M:%S")
    print("%s %6d  %7d  %7d  %10d  %10d  %7d  %10d  %7d  %8d" %
        (timeStr, proc_s, cswch_s, runqlen, dtaIrq, dtaSoft, 
        dtaIdle, dtaKT, dtaSysc, dtaUTime) )

    line += 1
    if line == 12:
        print("\n", thead_str)
        line = 0
    # bpf.trace_print()