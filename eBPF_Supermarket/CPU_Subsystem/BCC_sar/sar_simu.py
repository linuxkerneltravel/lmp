#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from bcc.utils import printb
import time, argparse, configparser
import ctypes, bpfutil

CONFIGFILE = "config.ini"
config = configparser.ConfigParser()
config.read(CONFIGFILE)

def parse_arg():
    parser = argparse.ArgumentParser(description="CPU subsystem parameter display")
    parser.add_argument("-i", "--interval", default=1, type=int,
        help="interval between two output, in second")
    parser.add_argument("--type", choices=["time", "percent"], 
        default="time", help="the way to show numbers, default in time")
    parser.add_argument("--count", default=99999999, type=int,
        help="count of outputs, default infinity")
    parser.add_argument("-p", "--process", type=int, 
        default=bpfutil.get_pid_by_name("dd"),
        help="the process that needs to be attached to, default whole kernel")
    return parser.parse_args()

def attach_probe():
    # load BPF program
    bpf = BPF(src_file="sar.c")
    bpf.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_sched_switch")
    bpf.attach_tracepoint(tp="irq:softirq_entry", fn_name="trace_softirq_entry")
    bpf.attach_tracepoint(tp="irq:softirq_exit", fn_name="trace_softirq_exit")
    # bpf.attach_tracepoint(tp="sched:sched_process_fork", fn_name="trace_sched_process_fork")
    bpf.attach_kprobe(event="update_rq_clock", fn_name="update_rq_clock")
    bpf.attach_tracepoint(tp="irq:irq_handler_entry", fn_name="trace_irq_handler_entry")
    bpf.attach_tracepoint(tp="irq:irq_handler_exit", fn_name="trace_irq_handler_exit")
    bpf.attach_tracepoint(tp="power:cpu_idle", fn_name="trace_cpu_idle")

    bpf.attach_tracepoint(tp="raw_syscalls:sys_enter", fn_name="trace_sys_enter")
    bpf.attach_tracepoint(tp="raw_syscalls:sys_exit", fn_name="trace_sys_exit")
    bpf.attach_kprobe(event="exit_to_user_mode_prepare",fn_name="exit_to_user_mode_prepare")

    # 上下文切换完成后的函数，包含了当前进程的ts和过去进程的ts
    bpf.attach_kprobe(event_re="^finish_task_switch$|^finish_task_switch\.isra\.\d$",
                    fn_name="finish_sched")

    # 传递给bpf程序的定时事件
    bpf.attach_perf_event(ev_type=PerfType.SOFTWARE,
        ev_config=PerfSWConfig.CPU_CLOCK,
        fn_name="tick_update",
        sample_period=0, 
        sample_freq=config.getint("numbers", "sample_freq")
    )
    
    return bpf

num_cpus = bpfutil.get_num_cpus()

args = parse_arg()
# print(args.process, args.interval)
bpf = attach_probe()
startTime = time.time()

print("Search kernel Symbols in /proc/kallsyms")
# 找runqueues会找到以下两种，所以需要限制尾部严格相同
# b'0000000000034e80 A runqueues\n'
# b'ffffffff8230b040 t sync_runqueues_membarrier_state\n'
addr = bpfutil.find_ksym("total_forks")
bpf['symAddr'][0] = ctypes.c_longlong(int(addr, base=16))


print("Tracing for Data's... Ctrl-C to end")
thead_str = {
    "time":     r"  time   proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms sys/ms",
    "percent":  r"  time   proc/s  cswch/s  runqlen   irqTime/%   softirq/%   idle/%   kthread/%   sysc/%   utime/%  sys/%"
}
print(thead_str[args.type])

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
userTime = 0

_line = line = 0
procAll = bpfutil.SecondRecord()
procSysc = bpfutil.SecondRecord()
procIrq = bpfutil.SecondRecord()

# 测试idlePidList的功能
# while 1:
#     printList(bpf['idlePid'])
#     time.sleep(2)

while 1:
    if args.interval > 0:
        time.sleep(args.interval)
    else:
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
    dtaIrq = (irqTime - _irqTime) # 多个CPU的irq时间总和，单位ns

    # irq占用时间
    _softTime = softTime
    softTime = bpf["softirqLastTime"][0].value
    dtaSoft = (softTime - _softTime) # 多个CPU的softirq时间总和，单位ns

    # IDLE时间
    _idleTime = idleTime
    idleTime = bpf['idleLastTime'][0].value
    dtaIdle = (idleTime - _idleTime) # ns

    # kthread运行时间
    _ktLastTime = ktLastTime
    ktLastTime = bpf['ktLastTime'][0].value
    dtaKT = (ktLastTime - _ktLastTime) # ns

    # syscall占用时间
    _syscTime = syscTime
    syscTime = bpf['syscTime'][0].value
    dtaSysc = (syscTime - _syscTime)

    # userThread占用时间
    _utLastTime = utLastTime
    utLastTime = bpf['utLastTime'][0].value
    dtaUTime = utLastTime - _utLastTime
    dtaUTime = (dtaUTime - (syscTime - _syscTime))

    # 记录直接统计的（相较于总体-Sysc的）的用户态占用时间
    _userTime = userTime
    userTime = bpf['userTime'][0].value
    dtaUTRaw = userTime - _userTime

    # 记录总的Sysc时间
    dtaSys = dtaKT + dtaSysc

    # 根据展示类型展示
    timeStr = time.strftime("%H:%M:%S")
    if args.type == "time":
        # key = ctypes.c_int32(args.process)
        print("%s %6d  %7d  %7d  %10d  %10d  %7d  %10d  %7d  %8d %6d" %
            (timeStr, proc_s, cswch_s, runqlen, dtaIrq / 1000, dtaSoft / 1000, 
            dtaIdle / 1000000, dtaKT / 1000, dtaSysc / 1000000, dtaUTRaw / 1000000,
            dtaSys / 1000000,
             ) )

        # procAll.UpRd(bpf["procAllTime"][key].value) / 1000000,
        #     procSysc.UpRd(bpf["procSyscTime"][key].value) / 1000000,
        #     procIrq.UpRd(bpf["procIrqTime"][key].value) / 1000000
    else:
        dtaIrq = float(dtaIrq) / num_cpus / 1000_000_0
        dtaSoft = float(dtaSoft) / num_cpus / 1000_000_0
        dtaIdle = float(dtaIdle) / num_cpus / 1000_000_0
        dtaKT = float(dtaKT) / num_cpus / 1000_000_0
        dtaSysc = float(dtaSysc) / num_cpus / 1000_000_0
        # dtaUTime = float(dtaUTime) / num_cpus / 1000_000_0
        dtaUTRaw = float(dtaUTRaw) / num_cpus / 1000_000_0
        dtaSys = float(dtaSys) / num_cpus / 1000_000_0

        print("%s %6d  %7d  %7d  %10.1f  %10.1f  %7.1f  %10.1f  %7.1f  %8.1f %6.1f" %
            (timeStr, proc_s, cswch_s, runqlen, dtaIrq, dtaSoft, 
            dtaIdle, dtaKT, dtaSysc, dtaUTRaw, dtaSys, ) )

    _line += 1
    line += 1
    # 到达了限定的退出次数
    if line >= args.count:
        break

    # 需要再次打印表头
    if _line == config.getint("numbers", "thead_reprint_lines"):
        print("\n", thead_str[args.type])
        _line = 0
    # bpf.trace_print()