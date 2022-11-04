#!/usr/bin/python3

from __future__ import print_function
import datetime
from os import getpid
from time import sleep, time
from bcc import BPF, PerfType, PerfSWConfig
import bpfutil, ctypes, argparse
import json
import sys
import os
import psutil

from wakeup_utils import get_sleep_func, deltaTimeMgr, MetricsAverager

BEGIN_SLEEP = 1
END_SLEEP = 2
BEGIN_WAIT = 3
END_WAIT = 4
BEGIN_RUN = 5
END_RUN = 6

def parse_args():
    parser = argparse.ArgumentParser(description="Wakeup Monitoring System", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-t", "--type", default="time", help=
    """Type of output method.
1. event: Write event to file. (May cause lost of information)
2. time: print time of sleep,run,wait and compares their addition with actual time.
        -- Since our eBPF program is event driven, the static process like pid 1(systemd) 
        which don't cause any event won't be recorded, so their value may become less.
3. flame: Output Flame Format TextFile to Produce frame SVG.
    """)
    parser.add_argument("-p", "--pid", default=0, type=int, 
        help="The Process needs to be attached on.")
    parser.add_argument("--time", default=3, type=float, help="excution time")
    parser.add_argument("--filter", default="Begin_Run", type=str, help="Type of event to filter.")
    parser.add_argument("-o", "--output", default="event.txt", type=str, 
        help="The output file which saves all the content.")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    bpf = BPF(src_file="wakeup.c")
    bpf.attach_tracepoint(tp="sched:sched_wakeup", fn_name="trace_wakeup")
    bpf.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_sched_switch")

    # 分别挂载在一个函数的进入和退出
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

    # cpu偏移量
    __per_cpu_offset = int(bpfutil.find_ksym("__per_cpu_offset"), base=16) # u32 array, Inited
    # runqueues, 运行队列的percpu变量
    runqueues = int(bpfutil.find_ksym("runqueues"), base=16) # per_cpu var, u32
    __preempt_count = int(bpfutil.find_ksym("__preempt_count"), base=16) # int, 32bit

    bpf['symAddr'][0] = ctypes.c_ulonglong(__per_cpu_offset)
    bpf['symAddr'][1] = ctypes.c_ulonglong(runqueues)
    bpf['symAddr'][2] = ctypes.c_ulonglong(__preempt_count) # 抢占标志位
    # 计算方式：某个cpu的PERCPU变量的地址 = PERCPU变量的地址 + __per_cpu_offset[cpu]

    # 传递自己的PID，使BPF避开这个pid，这件事非常重要！
    bpf["ownPid"][0] = ctypes.c_int(getpid())

    target_pid = args.pid
    nowtime = 0

    '''
    # 把栈信息写入到文件中
    def onexit():
        with open("sleep_stack.txt", "w") as f:
            for pid in pidSleepMap.keys():
                f.write("pid {}:\n".format(pid))
                for str in pidSleepMap[pid]:
                    f.write(str)
                    f.write("\n")
                f.write("\n")

        # 诀窍：读取schedule栈后(可用含有schedule来表示)的第一个函数
        with open("stack_type.txt", "w") as f:
            for stack in stack_set:
                f.write(stack)
                f.write("\n")

        print("Already Write.")
    atexit.register(onexit)
    '''

    # type=time: 打印某个进程在运行时的运行、等待、睡眠事件占比
    if args.type == "time":
        thead = r"%runTime  %waitTime  %sleepTime  allTime/ms  elapsed/ms  sleepTime/ms  runTime/us  runslice/us  runCount"
        print(thead)
        deltaMgr = deltaTimeMgr(4)

        sleepTime = MetricsAverager()
        runTime = MetricsAverager()
        runsliceTime = MetricsAverager()
        runCount = MetricsAverager()

        sleepStart = {}
        runStart = {}
        runTimeMap = {}
        def metric_record(cpu, data, size):
            global sleepStart, runStart, runTimeMap
            global sleepTime, runTime, runsliceTime, runCount
            # 成员：pid, comm, type, stackid, waker, waker_comm, time
            event = bpf["events"].event(data)

            pid = event.pid
            if pid != args.pid: return

            # comm = event.comm.decode('utf-8')
            # waker_comm = event.waker_comm.decode('utf-8')

            if event.type == BEGIN_SLEEP:
                # wchan = get_sleep_func(bpf, event.stackid)
                sleepStart[pid] = event.time

                if pid in runTimeMap:
                    count = len(runTimeMap[pid])
                    sum_time = 0
                    for i in runTimeMap[pid]:
                        sum_time += i
                    runCount.add(count)
                    runTime.add(sum_time)
                    runTimeMap.clear()

            elif event.type == END_SLEEP:
                if pid not in sleepStart: return
                time = (event.time - sleepStart[pid]) / 1000 # us
                del sleepStart[pid] # 删除键pid，表示pid已不在睡眠状态中了
                sleepTime.add(time)
            
            elif event.type == BEGIN_RUN:
                runStart[pid] = event.time

            elif event.type == END_RUN:
                if pid not in runStart: return
                time = (event.time - runStart[pid]) / 1000
                runsliceTime.add(time)

                if pid not in runTimeMap:
                    runTimeMap[pid] = []

                runTimeMap[pid].append(time)

        bpf["events"].open_perf_buffer(metric_record, page_cnt=128)
        while 1:
            runlast = waitlast = sleeplast = 0

            if ctypes.c_uint32(target_pid) in bpf["runlast"]: 
                runlast = bpf['runlast'][ctypes.c_uint32(target_pid)].value
            if ctypes.c_uint32(target_pid) in bpf["waitlast"]: 
                waitlast = bpf['waitlast'][ctypes.c_uint32(target_pid)].value
            if ctypes.c_uint32(target_pid) in bpf["sleeplast"]: 
                sleeplast = bpf['sleeplast'][ctypes.c_uint32(target_pid)].value
            all = runlast + waitlast + sleeplast

            runlast, waitlast, sleeplast, all = deltaMgr.update([runlast, waitlast, sleeplast, all])

            if all != 0:
                # sleepTime/ms  runTime/us  runslice/us  runCount
                print("%8.2f  %9.2f  %9.2f  %10d  %10d  %12.1f  %10.1f  %12.1f  %8.1f" % 
                    (runlast / all * 100, waitlast / all * 100, sleeplast / all * 100,
                    int(all / 1000000), 1000, 
                    sleepTime.recent()/1000, runTime.recent(), 
                    runsliceTime.recent(), runCount.recent() ) )
            else: # 避免除以0
                print("%8.2f  %9.2f  %9.2f  %10d  %10d  %12.1f  %10.1f  %12.1f  %8.1f" % 
                    (0, 0, 0, int(all / 1000000), 1000,
                    sleepTime.recent()/1000, runTime.recent(), 
                    runsliceTime.recent(), runCount.recent() ) )
            
            bpf.perf_buffer_poll()
            sleep(1)
            nowtime += 1
            if nowtime % 12 == 0:
                print()
                print(thead)

    # type=event: 生成事件日志，包括运行、等待、睡眠
    elif args.type == 'event':
        pidEvent = {} # 存储每个pid的event列表
        f = open(args.output, "w")

        # 记录type序号对应的事件类型
        typeNameMap = {
            1: "Begin_Sleep",
            2: "End_Sleep",
            3: "Begin_Wait",
            4: "End_Wait",
            5: "Begin_Run",
            6: "End_Run"
        }

        # perf数据接收回调函数
        def print_event(cpu, data, size):
            global cnt
            cnt += 1
            # 成员：pid, comm, type, stackid, waker, waker_comm, time
            event = bpf["events"].event(data)

            pid = event.pid
            stackid = event.stackid

            comm = event.comm.decode('utf-8')
            waker_comm = event.waker_comm.decode('utf-8')

            # 若当前类型为BeginSleep或者EndSleep，读取栈信息到stack_str中
            if event.type <= 2:
                # 对于BEGIN_SLEEP, 打印wchan
                stack_str = ""
                if event.type == BEGIN_SLEEP:
                    stack_str = get_sleep_func(bpf, stackid)
                else: # END_SLEEP
                    # 之后可能做一下数据分类，现在先只用第一项
                    for addr in bpf["stacktraces"].walk(stackid):
                        sym = bpf.ksym(addr).decode('utf-8', 'replace')
                        # 采集整个栈的信息
                        # stack_str = stack_str + "\t" + sym + "\n"
                        stack_str = sym
                        break
            else:
                stack_str = "None"

            if pid not in pidEvent:
                pidEvent[pid] = []

            # if typeNameMap[event.type] not in ["End_Sleep", "End_Run", "End_Wait"]:
            try:
                pid_str = "#%d pid:%d %s type:%s waker:%d %s time:%dus\n%s\n\n" \
                    % (cnt, pid, comm, typeNameMap[event.type], 
                    event.waker, waker_comm, int(event.time / 1000), 
                    stack_str)
            except Exception as e:
                print(e)
                os._exit(0)

            # 如果配置了pid项，那么只打印与该pid有关的事件
            if args.pid != 0:
                if pid == args.pid:
                    f.write(pid_str)
            else:
                f.write(pid_str)
            
            pidEvent[pid].append(pid_str)

        # 准备从perf_output中接收数据
        start = time()
        bpf["events"].open_perf_buffer(print_event, page_cnt=128)
        global cnt
        cnt = 0

        while 1:
            bpf.perf_buffer_poll()
            sleep(1)
            if time() - start > args.time:
                break

            # nowtime += 1
            # print(nowtime)
            # if nowtime == 10:
            #     break

        f.close() # 关闭文件
        print("EVENT cnt = ", cnt)
        print("Tracepoint count = ", bpf["countMap"][0].value)

    # type=flame: 生成火焰图所需要的格式化文件
    elif args.type == "flame":
        f = open(args.output, "w")
        runbegin = {}
        runEnd = {}

        # 检查是否设置专门监测某一个pid
        pid_configured = (args.pid != 0)

        if pid_configured:
            print("只跟踪pid = {}进程的活动".format(args.pid))

        def flame_record(cpu, data, size):
            # 成员：pid, comm, type, stackid, waker, waker_comm, time
            event = bpf["events"].event(data)

            pid = event.pid
            comm = event.comm.decode('utf-8')
            # waker_comm = event.waker_comm.decode('utf-8')

            if cpu != 0: return

            if event.type == BEGIN_RUN:
                runbegin[pid] = event.time
                if pid_configured and pid == args.pid and pid in runEnd:
                    time = int((event.time - runEnd[pid]) / 1000)
                    f.write("{0};{1} {2}\n".format(comm, "stop", time))

            # 如果配置了pid项，那么只输出对应pid的所有事件
            elif event.type == END_RUN and pid in runbegin:
                if pid != 0:
                    time = int((event.time - runbegin[pid]) / 1000) # us
                else:
                    time = 3 # idle进程的运行时间一律设为3个单位，以优化显示

                if (pid_configured and pid == args.pid) or (not pid_configured):
                    f.write("{0};{1} {2}\n".format(comm, pid, time))

                runEnd[pid] = event.time

        bpf["events"].open_perf_buffer(flame_record, page_cnt=128)
        start = time()
        while 1:
            bpf.perf_buffer_poll()
            sleep(1)
            if time() - start > args.time:
                break

    # type=lifeline：生成某个进程的生命周期数据，只包括运行和睡眠
    elif args.type == "lifeline":
        f = open(args.output, "w")
        sleep_start = -1
        run_start = -1
        print("跟踪pid = {}进程的生命周期...".format(args.pid))

        def flame_record(cpu, data, size):
            global sleep_start, run_start
            # 成员：pid, comm, type, stackid, waker, waker_comm, time
            event = bpf["events"].event(data)

            pid = event.pid
            if pid != args.pid: return

            comm = event.comm.decode('utf-8')
            waker_comm = event.waker_comm.decode('utf-8')

            if event.type == BEGIN_SLEEP:
                wchan = get_sleep_func(bpf, event.stackid)
                # BPF 获取到的timestamp实际上是系统的启动时间，先留置
                # 之后再转换为时分秒
                sleep_start = event.time
                f.write("{}: [cpu{}] {}-{} Begin_Sleep on {}\n".format(event.time, 
                    cpu, pid, comm, wchan))

            elif event.type == END_SLEEP:
                if sleep_start != -1:
                    time = ((event.time - sleep_start) / 1000000)
                else:
                    time = -1

                stack_str = ""
                for addr in bpf["stacktraces"].walk(event.stackid):
                    sym = bpf.ksym(addr).decode('utf-8', 'replace')
                    # 采集整个栈的信息
                    stack_str = stack_str + "\t" + sym + "\n"
                    # break

                f.write("%d: [cpu%d] %d-%s End_Sleep lasting %.1fms (wake by %d-%s, context %d)\n%s\n"
                    % (event.time, cpu, pid, comm, time, 
                    event.waker, waker_comm, event.preempt_count, stack_str))
            
            elif event.type == BEGIN_RUN:
                run_start = event.time

            elif event.type == END_RUN:
                if run_start != -1:
                    time = int((event.time - run_start) / 1000) # us
                else:
                    time = -1
                f.write("%d: [cpu%d] %d-%s Run for %dus\n" % (event.time, cpu,
                    pid, comm, time))

        bpf["events"].open_perf_buffer(flame_record, page_cnt=128)
        start = time()
        while 1:
            bpf.perf_buffer_poll()
            sleep(1)
            if time() - start > args.time:
                break

    # 生成进程的状态切换JSON文件，写入到python_exporter目录下
    elif args.type == "json":
        print("Monitoring process pid = %d" % args.pid)
        f = open("../../exporter/metrics.json", "w") # 写死的输出路径，之后可以改
        waker_comm = ""
        jsonMap = []
        boot_time = psutil.boot_time()  # 系统启动时间戳
        curState = "run"

        def flame_record(cpu, data, size):
            global waker_comm, curState
            # 成员：pid, comm, type, stackid, waker, waker_comm, time
            event = bpf["events"].event(data)
            if event.pid != args.pid: return
            # event.time是相对于系统启动时间的时间戳

            nowtime = boot_time + event.time / 1000000000

            if event.type == BEGIN_RUN:
                curState = "run"
                jsonMap.append({"time": nowtime, "state": "run-cpu%d" % cpu, "pid": args.pid, "evt_time": event.time})

            elif event.type == BEGIN_SLEEP:
                curState = "sleep"
                wchan = get_sleep_func(bpf, event.stackid)
                jsonMap.append({"time": nowtime, "state": "sleep-%s" % (wchan,), "pid": args.pid, "evt_time": event.time})

            elif event.type == BEGIN_WAIT:
                info = "" if curState == "run" else waker_comm
                jsonMap.append({"time": nowtime, "state": "wait-%s" % (info,), "pid": args.pid, "evt_time": event.time})

            elif event.type == END_SLEEP:
                waker_comm = event.waker_comm.decode('utf-8')

        bpf["events"].open_perf_buffer(flame_record, page_cnt=128)
        start = time()
        while 1:
            bpf.perf_buffer_poll()
            sleep(1)
            if time() - start > args.time:
                break

        json_str = json.dumps(jsonMap)
        f.write(json_str)
        f.close()
        print("Produce %d Records." % len(jsonMap))
    
    '''
    # perf缓冲区的用法(previous)
    def print_event(cpu, data, size):
        event = bpf["events"].event(data)
        print("recv msg.")

    # loop with callback to print_event
    bpf["events"].open_perf_buffer(print_event)

    while 1:
        bpf.perf_buffer_poll() # 仅适用于与poll不发生牵连影响的perf_submit
    '''