#!/usr/bin/python3

from __future__ import print_function
from time import sleep, time
from bcc import BPF, PerfType, PerfSWConfig
import bpfutil, ctypes, argparse

BEGIN_SLEEP = 1
END_SLEEP = 2
BEGIN_WAIT = 3
END_WAIT = 4
BEGIN_RUN = 5
END_RUN = 6

# 方便的管理数据随时间的更改，并能计算变化量
class deltaTimeMgr:
    def __init__(self, cnt: int) -> None:
        self.container = [0 for _ in range(cnt)]
        self.delta = [0 for _ in range(cnt)]
        self.cnt = cnt

    def update(self, lst) -> list:
        if len(lst) != self.cnt:
            raise Exception("列表长度不匹配")
        else:
            for i in range(len(lst)):
                self.delta[i] = lst[i] - self.container[i]
                self.container[i] = lst[i]
            return self.delta

def parse_args():
    parser = argparse.ArgumentParser(description="Wakeup Monitoring System")
    parser.add_argument("-t", "--type", default="time", help=
    """Type of output method.\n
    event: print event to screen. (May cause lost of information)
    time: print time of sleep,run,wait and compares their addition with actual time.
        -- Since our eBPF program is event driven, the static process like pid 1(systemd) which don't cause any event
        won't be recorded, so their value may become less.
    """)
    parser.add_argument("-p", "--pid", default=0, type=int, help="The Process needs to be attached on.")
    parser.add_argument("--time", default=3, type=float, help="excution time")

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

    bpf['symAddr'][0] = ctypes.c_ulonglong(__per_cpu_offset)
    bpf['symAddr'][1] = ctypes.c_ulonglong(runqueues)
    # 计算方式：某个cpu的PERCPU变量的地址 = PERCPU变量的地址 + __per_cpu_offset[cpu]

    pidEvent = {}

    f = open("event.txt", "w")

    # perf数据接收回调函数
    def print_event(cpu, data, size):
        # 成员：pid, comm, type, stackid, waker, waker_comm, time
        event = bpf["events"].event(data)
        stacktraces = bpf["stacktraces"]

        pid = event.pid
        stackid = event.stackid

        comm = event.comm.decode('utf-8')
        waker_comm = event.waker_comm.decode('utf-8')

        # 读取栈信息到stack_str中
        if event.type <= 2:
            stack_str = ""
            for addr in stacktraces.walk(stackid):
                sym = bpf.ksym(addr).decode('utf-8', 'replace')
                stack_str = stack_str + "\t" + sym + "\n"
        else:
            stack_str = "None"

        if pid not in pidEvent:
            pidEvent[pid] = []

        pid_str = "{} {} type={} {} {} {}us\n{}\n\n".format(pid, comm, event.type, 
                    event.waker, waker_comm, int(event.time / 1000), stack_str)
        pidEvent[pid].append(pid_str)

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

    if args.type == "time":
        thead = r"%runTime  %waitTime  %sleepTime  allTime/ms  elapsed/ms"
        print(thead)
        deltaMgr = deltaTimeMgr(4)
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
                print("%8.2f  %9.2f  %9.2f  %10d  %10d" % 
                    (runlast / all, waitlast / all, sleeplast / all, int(all / 1000000), 1000) )
            else:
                print("%8.2f  %9.2f  %9.2f  %10d  %10d" % 
                    (0, 0, 0, int(all / 1000000), 1000) )
            
            sleep(1)
            nowtime += 1
            if nowtime % 12 == 0:
                print()
                print(thead)

    elif args.type == 'event':
        # 准备从perf_output中接收数据
        start = time()
        bpf["events"].open_perf_buffer(print_event) 

        while 1:
            bpf.perf_buffer_poll(timeout=1000)
            if time() - start > args.time:
                break

            # nowtime += 1
            # print(nowtime)
            # if nowtime == 10:
            #     break

    '''
    # perf缓冲区的用法
    def print_event(cpu, data, size):
        event = bpf["events"].event(data)
        print("recv msg.")

    # loop with callback to print_event
    bpf["events"].open_perf_buffer(print_event)

    while 1:
        bpf.perf_buffer_poll()
    '''