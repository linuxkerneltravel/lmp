#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from bcc.utils import printb
import time, argparse, configparser
import ctypes, signal
from .. import bpfutil
from ..bpfutil import colorize

def parse_arg():
    parser = argparse.ArgumentParser(description="CPU subsystem parameter display")
    parser.add_argument("-i", "--interval", default=1, type=int,
        help="interval between two output, in second")
    parser.add_argument("-t", "--type", choices=["time", "percent"], 
        default="time", help="the way to show numbers, default in time")
    parser.add_argument("-c", "--count", default=99999999, type=int,
        help="count of outputs, default infinity")
    parser.add_argument("-p", "--process", type=int, 
        default=-1,
        help="the process that needs to be attached to, default whole kernel")
    return parser.parse_args()

def attach_probe():
    # load BPF program
    bpf = BPF(src_file="sar.bpf.c")
    bpf.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_sched_switch")
    bpf.attach_tracepoint(tp="irq:softirq_entry", fn_name="trace_softirq_entry")
    bpf.attach_tracepoint(tp="irq:softirq_exit", fn_name="trace_softirq_exit")
    bpf.attach_kprobe(event="update_rq_clock", fn_name="update_rq_clock")
    bpf.attach_tracepoint(tp="irq:irq_handler_entry", fn_name="trace_irq_handler_entry")
    bpf.attach_tracepoint(tp="irq:irq_handler_exit", fn_name="trace_irq_handler_exit")
    bpf.attach_tracepoint(tp="power:cpu_idle", fn_name="trace_cpu_idle")

    bpf.attach_tracepoint(tp="raw_syscalls:sys_enter", fn_name="trace_sys_enter")
    bpf.attach_tracepoint(tp="raw_syscalls:sys_exit", fn_name="trace_sys_exit")
    # bpf.attach_kprobe(event="exit_to_user_mode_prepare",fn_name="exit_to_user_mode_prepare")

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

def main():
    global config
    CONFIGFILE = "../../config/config.ini"
    config = configparser.ConfigParser()
    config.read(CONFIGFILE)

    num_cpus = bpfutil.get_num_cpus()
    args = parse_arg()

    global exiting
    exiting = 0

    def exit_app(signum, frame):
        global exiting
        exiting = 1

    signal.signal(signal.SIGINT, exit_app)

    if args.process >= 0:
        import sar_perpro
        sar_perpro.perpro_main(args, args.process)
        return

    bpf = attach_probe()

    # print("Search kernel Symbols in /proc/kallsyms")
    # 找runqueues会找到以下两种，所以需要限制尾部严格相同
    # b'0000000000034e80 A runqueues\n'
    # b'ffffffff8230b040 t sync_runqueues_membarrier_state\n'
    addr = bpfutil.find_ksym("total_forks")
    bpf['symAddr'][0] = ctypes.c_longlong(int(addr, base=16))


    print("Tracing for Data's... Ctrl-C to end")
    thead_str = {
        # 需要严格保持每两个表项之间间隔两个空格
        "time":     r"  time    proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms  sys/ms  syscFreq",
        "percent":  r"  time    proc/s  cswch/s  runqlen   irqTime/%   softirq/%   idle/%   kthread/%   sysc/%   utime/%   sys/%  syscFreq"
    }
    print(thead_str[args.type])

    # 长期保存的数值
    proc = 0
    cswch = 0
    irqTime = 0
    softTime = 0
    idleTime = 0
    ktLastTime = 0
    syscTime = 0
    utLastTime = 0
    userTime = 0
    syscCount = 0
    tick_user = 0
    sums = [0 for _ in range(11)]

    _line = line = 0

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

        # syscall占用时间(纯syscall时间，不含BPF执行时间)
        _syscTime = syscTime
        syscTime = bpf['syscTime'][0].value
        dtaSysc = (syscTime - _syscTime)

        # userThread占用时间
        _utLastTime = utLastTime
        utLastTime = bpf['utLastTime'][0].value
        dtaUTLastTime = utLastTime - _utLastTime

        # 记录直接统计的（相较于总体-Sysc的）的用户态占用时间
        _userTime = userTime
        userTime = bpf['userTime'][0].value
        dtaUTRaw = userTime - _userTime

        # 记录syscall的频率
        _syscCount = syscCount
        syscCount = bpf["countMap"][2].value
        dtaSyscCount = syscCount - _syscCount

        # 第一次的数据不准，不予记录
        if line != 0:
            # 记录总值，以计算平均值
            sums[0]  += proc_s  
            sums[1]  += cswch_s 
            sums[2]  += runqlen 
            sums[3]  += dtaIrq  
            sums[4]  += dtaSoft 
            sums[5]  += dtaIdle 
            sums[6]  += dtaKT   
            sums[7]  += dtaSysc 
            sums[8]  += dtaUTRaw
            sums[9]  += dtaSys  
            sums[10] += dtaSyscCount

        # 最后一次打印，要输出平均值
        if line == args.count or exiting == 1:
            timeStr = "Average"
            # 计算平均值
            proc_s         = sums[0] / line
            cswch_s        = sums[1] / line
            runqlen        = sums[2] / line
            dtaIrq         = sums[3] / line
            dtaSoft        = sums[4] / line
            dtaIdle        = sums[5] / line
            dtaKT          = sums[6] / line
            dtaSysc        = sums[7] / line
            dtaUTRaw       = sums[8] / line
            dtaSys         = sums[9] / line
            dtaSyscCount   = sums[10] / line
            print("\n", thead_str[args.type])
        else:
            timeStr = time.strftime("%H:%M:%S")
        
        _tick_user = tick_user
        tick_users = bpf['tick_user'][0]
        tick_user = 0
        for i in tick_users:
            tick_user += i
        dtaTickUser = tick_user - _tick_user

        # 这一段用tick计算的userTime来替换之前用syscall计算的userTime
        dtaUTRaw = dtaTickUser / config.getint("numbers", "sample_freq") * 1000000000
        dtaSys = dtaUTLastTime - dtaUTRaw + dtaKT # 含BPF时间，dtaSys - dtaKT - dtaSysc大概是BPF时间的一半
        # 普通用户进程可近似看做只含有usr和syscall(省略了irq & softirq)

        # 按照类型输出信息
        if args.type == "time": # 输出时间型
            print("%8s  %6d  %7d  %7d  %10d  %10d  %7d  %10d  %7d  %8d  %6d  %8d" %
                (timeStr, proc_s, cswch_s, runqlen, dtaIrq / 1000, dtaSoft / 1000, 
                dtaIdle / 1000000, dtaKT / 1000, dtaSysc / 1000000, dtaUTRaw / 1000000,
                dtaSys / 1000000, dtaSyscCount
                ) )
        else:
            fmt = ["%8s", "%6d", "%7d", "%7d", "%10.1f", "%10.1f", "%7.1f", "%10.1f", "%7.1f", "%8.1f", "%6.1f", "%8d"]
            nums = [timeStr, proc_s, cswch_s, runqlen, dtaIrq, dtaSoft, dtaIdle, dtaKT, dtaSysc, dtaUTRaw, dtaSys, dtaSyscCount]
            
            # 自动检查格式并匹配
            target = []
            for i in range(len(fmt)):
                if 's' in fmt[i]:
                    target.append(fmt[i] % nums[i])
                elif 'd' in fmt[i]:
                    # 直接代入即可
                    target.append(colorize(34, fmt[i] % nums[i]))
                elif 'f' in fmt[i]:
                    # 一般是代入百分比的
                    nums[i] = float(nums[i]) / num_cpus / args.interval / 1000_000_0
                    
                    str = fmt[i] % nums[i]
                    if nums[i] < 30:
                        color = 34 # blue
                    elif nums[i] < 60:
                        color = 32 # green
                    else:
                        color = 31 # red
                    target.append(colorize(color, str))
                else:
                    target.append(' ')

            print(("%s  " * len(target)) % tuple(target))

        _line += 1
        line += 1
        # 到达了限定的退出次数
        if line >= args.count + 1 or exiting == 1:
            break

        # 需要再次打印表头
        if _line == config.getint("numbers", "thead_reprint_lines"):
            print("\n", thead_str[args.type])
            _line = 0

        # 打印BPF程序中的输出
        # bpf.trace_print()

if __name__ == "__main__":
    main()