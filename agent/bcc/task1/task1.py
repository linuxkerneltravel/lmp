#!/usr/bin/python
#
# This is a Hello World example that uses BPF_PERF_OUTPUT.

from bcc import BPF
from bcc.utils import printb
from prometheus_client import Gauge
# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")


#每个bcc文件中需要增加create方法
#该方法中定义 open_perf_buffer 绑定的方法
#定义需要输出的指标
#返回调整后的BPF对象
def create(reg):
    
    #metrics = Gauge('task1_metric',registry=reg)
    #定义输出的指标mitrics，指定名称及其所属的文件名
    metrics = Gauge('times','task1Metric')
    start = [0]
    # 定义 open_perf_buffer 绑定的方法
    def print_event(cpu, data, size):
        
        event = b["events"].event(data)
        if start[0] == 0:
            start[0] = event.ts
        time_s = (float(event.ts - start[0])) / 1000000000
        #给指标赋值
        metrics.set(time_s)
    # 为open_perf_buffer 绑定方法
    b["events"].open_perf_buffer(print_event)
    return b
    
  
    
