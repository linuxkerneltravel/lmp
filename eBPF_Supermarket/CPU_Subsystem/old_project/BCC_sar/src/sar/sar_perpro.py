#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
import time, configparser
import ctypes, bpfutil
from bpfutil import colorize
import psutil, signal

ID_schedCount = 0
ID_startTime = 1
ID_threadLastTime = 2
ID_userTime = 3
ID_softirqEnterTime = 4
ID_softirqLastTime = 5
ID_irqEnterTime = 6
ID_irqLastTime = 7
ID_syscTime = 8

def attach_probe(pid: int):
    # load BPF program
    filename = "sar_perpro.bpf.c"
    with open(filename, "r") as f:
        lines = f.readlines()
    lines[2] = "#define TARGET_PID {}\n".format(pid)
    with open(filename, "w") as f:
        f.writelines(lines)

    bpf = BPF(src_file=filename)
    bpf.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_sched_switch")
    bpf.attach_tracepoint(tp="irq:softirq_entry", fn_name="trace_softirq_entry")
    bpf.attach_tracepoint(tp="irq:softirq_exit", fn_name="trace_softirq_exit")
    bpf.attach_tracepoint(tp="irq:irq_handler_entry", fn_name="trace_irq_handler_entry")
    bpf.attach_tracepoint(tp="irq:irq_handler_exit", fn_name="trace_irq_handler_exit")
    bpf.attach_tracepoint(tp="raw_syscalls:sys_enter", fn_name="trace_sys_enter")
    # bpf.attach_tracepoint(tp="raw_syscalls:sys_exit", fn_name="trace_sys_exit")
    # bpf.attach_kprobe(event="exit_to_user_mode_prepare",fn_name="exit_to_user_mode_prepare")
    return bpf

def perpro_main(args, pid: int):
    # 检查pid是否存在
    pids = psutil.pids()
    if pid not in pids:
        print(colorize(31, "ERR:") + " Process %d not exist. Please check the pid." % pid)
        return

    print("Attach on process %d." % pid)
    global exiting
    exiting = 0

    def exit_app(signum, frame):
        global exiting
        exiting = 1

    signal.signal(signal.SIGINT, exit_app)

    CONFIGFILE = "../../config/config.ini"
    config = configparser.ConfigParser()
    config.read(CONFIGFILE)

    num_cpus = bpfutil.get_num_cpus()
    bpf = attach_probe(pid)

    print("Tracing for Data's... Ctrl-C to end")
    thead_str = {
        "time":     r"  time   cswch/s  irqTime/us  softirq/us  sysc/us  utime/us  total/us",
        "percent":  r"  time   cswch/s   irqTime/%   softirq/%   sysc/%   utime/%   total/%"
    }
    print(thead_str[args.type])

    # 长期保存的数值
    cswch = 0
    irqTime = 0
    softTime = 0
    syscTime = 0
    utLastTime = 0
    userTime = 0

    sums = [0 for _ in range(7)]

    _line = line = 0

    while 1:
        # 1. 延时输出
        if args.interval > 0:
            time.sleep(args.interval)
        else:
            time.sleep(1)

        # 上下文切换数
        cswch_s = bpf["TotalMap"][ID_schedCount].value
        cswch_s, cswch = cswch_s - cswch, cswch_s

        # irq占用时间
        _irqTime = irqTime
        irqTime = bpf["TotalMap"][ID_irqLastTime].value
        dtaIrq = (irqTime - _irqTime) # 多个CPU的irq时间总和，单位ns

        # softirq占用时间
        _softTime = softTime
        softTime = bpf["TotalMap"][ID_softirqLastTime].value
        dtaSoft = (softTime - _softTime) # 多个CPU的softirq时间总和，单位ns

        # syscall占用时间
        _syscTime = syscTime
        syscTime = bpf['TotalMap'][ID_syscTime].value
        dtaSysc = (syscTime - _syscTime)

        # userThread占用时间(总)
        _utLastTime = utLastTime
        utLastTime = bpf['TotalMap'][ID_threadLastTime].value
        dtaAllTime = utLastTime - _utLastTime

        # 记录直接统计的（相较于总体-Sysc的）的用户态占用时间
        _userTime = userTime
        userTime = bpf['TotalMap'][ID_userTime].value
        dtaUTRaw = userTime - _userTime

        dtaAllTimeAdd = (dtaSysc + dtaUTRaw)

        # 第一次的数据不准，不予记录
        if line != 0:
            # 记录总值，以计算平均值
            sums[0] += cswch_s
            sums[1] += dtaIrq
            sums[2] += dtaSoft
            sums[3] += dtaSysc
            sums[4] += dtaUTRaw
            sums[5] += dtaAllTime
            sums[6] += dtaAllTimeAdd

        # 最后一次打印，要输出平均值
        if line == args.count or exiting == 1:
            timeStr = "Average"
            # 计算平均值
            cswch_s        = sums[0] / line
            dtaIrq         = sums[1] / line
            dtaSoft        = sums[2] / line
            dtaSysc        = sums[3] / line
            dtaUTRaw       = sums[4] / line
            dtaAllTime     = sums[5] / line
            dtaAllTimeAdd  = sums[6] / line
            print(colorize(32, "\nOn pid %d:\n" % pid), thead_str[args.type])
        else:
            # 根据展示类型展示
            timeStr = time.strftime("%H:%M:%S")
        
        if args.type == "time":
            print("%8s  %7d  %10d  %10d  %7d  %8d  %8d %d" %
                (timeStr, cswch_s, dtaIrq / 1000, dtaSoft / 1000, 
                dtaSysc / 1000, dtaUTRaw / 1000, dtaAllTime / 1000,
                dtaAllTimeAdd / 1000 ) )
        else:
            fmt = ["%8s", "%7d", "%10.1f", "%10.1f", "%7.1f", "%8.1f", "%8.1f"]
            nums = [timeStr, cswch_s, dtaIrq, dtaSoft, dtaSysc, dtaUTRaw, dtaAllTime]
            
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
                    nums[i] = float(nums[i]) / num_cpus / 1000_000_0
                    
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

            print("%s %s  %s  %s  %s  %s  %s" % tuple(target))

        _line += 1
        line += 1
        # 到达了限定的退出次数(count个实时输出 + 1个平均值)
        if line >= args.count + 1 or exiting == 1:
            break

        # 再次打印表头
        if _line == config.getint("numbers", "thead_reprint_lines"):
            print("\n", thead_str[args.type])
            _line = 0

class ARG:
    def __init__(self) -> None:
        self.type = ""
        self.count = self.interval = 1

if __name__ == "__main__":
    args = ARG()
    args.type = "time"
    args.interval = 1
    args.count = 999999

    perpro_main(args, 1537)