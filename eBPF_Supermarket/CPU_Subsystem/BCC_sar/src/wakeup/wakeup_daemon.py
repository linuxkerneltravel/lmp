#!/usr/bin/python3
# 此程序作为后台执行，每隔指定时间(比如10s)更新数据
from __future__ import print_function
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
    parser.add_argument("--time", default=3, type=float, help="Update time of daemon")
    parser.add_argument("--filter", default="Begin_Run", type=str, help="Type of event to filter.")
    parser.add_argument("-o", "--output", default="event.txt", type=str, 
        help="The output file which saves all the content.")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    bpf = BPF(src_file="wakeup.c")
    bpf.attach_tracepoint(tp="sched:sched_wakeup", fn_name="trace_wakeup")
    bpf.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_sched_switch")

    # 传递给bpf程序的定时事件
    bpf.attach_perf_event(ev_type=PerfType.SOFTWARE,
        ev_config=PerfSWConfig.CPU_CLOCK,
        fn_name="tick_update",
        sample_period=0, 
        sample_freq=3
    )

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

    # 生成进程的状态切换JSON文件，写入到python_exporter目录下
    elif args.type == "json":
        print("Monitoring process pid = %d" % args.pid)
        waker_comm = ""
        jsonMap = []
        boot_time = psutil.boot_time()  # 系统启动时间戳
        curState = "run"

        def commit_change():
            f = open("../../exporter/metrics.json", "w") # 写死的输出路径，之后可以改
            json_str = json.dumps(jsonMap)
            f.write(json_str)
            f.close()
            print("[ReWrite] Produce %d Records." % len(jsonMap))

        def flame_record(cpu, data, size):
            global waker_comm, curState
            # 成员：pid, comm, type, stackid, waker, waker_comm, time
            event = bpf["events"].event(data)
            if event.pid != args.pid: return
            # event.time是相对于系统启动时间的时间戳

            nowtime = boot_time + event.time / 1000000000
            toAdd = None

            if event.type == BEGIN_RUN:
                curState = "run"
                toAdd = {"time": nowtime, "state": "run-cpu%d" % cpu, "pid": args.pid, "evt_time": event.time}

            elif event.type == BEGIN_SLEEP:
                curState = "sleep"
                wchan = get_sleep_func(bpf, event.stackid)
                toAdd = {"time": nowtime, "state": "sleep-%s" % (wchan,), "pid": args.pid, "evt_time": event.time}

            elif event.type == BEGIN_WAIT:
                info = "" if curState == "run" else waker_comm
                toAdd = {"time": nowtime, "state": "wait-%s" % (info,), "pid": args.pid, "evt_time": event.time}

            if toAdd is not None:
                beginTime = toAdd["time"] - args.time
                # 删除不在[now-args.time, now]范围内的前几条数据
                while len(jsonMap) > 0 and jsonMap[0]["time"] < beginTime:
                    del jsonMap[0]
                jsonMap.append(toAdd)

            if event.type == END_SLEEP:
                waker_comm = event.waker_comm.decode('utf-8')

        bpf["events"].open_perf_buffer(flame_record, page_cnt=128)
        start = time()
        period_time = 0
        while 1:
            bpf.perf_buffer_poll()
            sleep(1)
            period_time += 1
            if period_time >= args.time:
                period_time = 0
                commit_change()
