#!/usr/bin/python3

from __future__ import print_function
from time import sleep
from bcc import BPF, PerfType, PerfSWConfig
import bpfutil, ctypes

bpf = BPF(src_file="wakeup.c")
bpf.attach_tracepoint(tp="sched:sched_wakeup", fn_name="trace_wakeup")
bpf.attach_tracepoint(tp="sched:sched_process_wait", fn_name="trace_wait")
bpf.attach_tracepoint(tp="sched:sched_stat_blocked",fn_name="trace_block")

# 传递给bpf程序的定时事件
bpf.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK,
    fn_name="tick_update",
    sample_period=0, 
    sample_freq=3
)

# 内核中的重要变量定义，留作参考，勿删！
# pcpu_base_addr = int(bpfutil.find_ksym("pcpu_base_addr"), base=16) # u32, Read Only
# __per_cpu_start = int(bpfutil.find_ksym("__per_cpu_start"), base=16) # u32, Read Only
# pcpu_unit_offsets = int(bpfutil.find_ksym("pcpu_unit_offsets"), base=16) # u32 array, Read Only

__per_cpu_offset = int(bpfutil.find_ksym("__per_cpu_offset"), base=16) # u32 array, Inited
runqueues = int(bpfutil.find_ksym("runqueues"), base=16) # per_cpu var, u32

bpf['symAddr'][0] = ctypes.c_ulonglong(__per_cpu_offset)
bpf['symAddr'][1] = ctypes.c_ulonglong(runqueues)
# print(bpfutil.find_ksym("__per_cpu_offset"))
# 计算方式：ptr_to_PERCPU_var + __per_cpu_offset[cpu]

while 1:
    sleep(1)