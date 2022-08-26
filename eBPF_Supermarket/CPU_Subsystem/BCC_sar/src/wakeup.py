#!/usr/bin/python3

from __future__ import print_function
from time import sleep
from bcc import BPF, PerfType, PerfSWConfig
import bpfutil, ctypes

bpf = BPF(src_file="wakeup.c")
bpf.attach_tracepoint(tp="sched:sched_wakeup", fn_name="trace_wakeup")
bpf.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_sched_switch")
# bpf.attach_kprobe(event="ttwu_do_wakeup", fn_name="ttwu_do_wakeup")

# bpf.attach_kprobe(event="wake_up_process", fn_name="kprobe_wake_up_process")

# bpf.attach_kprobe(event="try_to_wake_up", fn_name="kprobe_try_to_wake_up")
# bpf.attach_kretprobe(event="try_to_wake_up", fn_name="kretprobe_try_to_wake_up")

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

target_pid = 10327
nowtime = 0
while 1:
    runlast = waitlast = sleeplast = 0

    if ctypes.c_uint32(target_pid) in bpf["runlast"]: 
        runlast = bpf['runlast'][ctypes.c_uint32(target_pid)].value
    if ctypes.c_uint32(target_pid) in bpf["waitlast"]: 
        waitlast = bpf['waitlast'][ctypes.c_uint32(target_pid)].value
    if ctypes.c_uint32(target_pid) in bpf["sleeplast"]: 
        sleeplast = bpf['sleeplast'][ctypes.c_uint32(target_pid)].value
    
    all = runlast + waitlast + sleeplast
    # print(runlast / 1000000)
    # print(waitlast / 1000000)
    # print(sleeplast / 1000000)
    print(all / 1000000, nowtime * 1000)

    sleep(1)
    nowtime += 1

'''
# process event
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    print("recv msg.")

# loop with callback to print_event
bpf["events"].open_perf_buffer(print_event)

while 1:
    bpf.perf_buffer_poll()
'''