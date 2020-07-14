#!/usr/bin/python
# -*- coding: UTF-8 -*-

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from time import sleep
import signal
import argparse
import json
import time

#prometheus 链接相关的包
import prometheus_client
from prometheus_client import Gauge
from flask import Response, Flask
from prometheus_client.core import CollectorRegistry

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/rtc.h>

#include <linux/kernel_stat.h>
#include <linux/kallsyms.h>


// 定义输出数据的类型
struct data_t {
	//进程管理部分字段 -> task_struct
//以下是 tag：
    u32 pid;					//进程的pid号                  
    char comm[TASK_COMM_LEN];	//进程的应用程序名字             
//以下是 field：    
     
    u64 utime;                  //进程用户态耗费的时间            
    u64 stime;                  //进程内核态耗费的时间            				
    u64 sum_exec_runtime;       //已经运行的时间总和              
    u64 vruntime;				//虚拟运行时间                   
    
};

//数据输出的通道
BPF_PERF_OUTPUT(events);
//typedef u64(*get_time_idle_type)(int);

int process_time(struct pt_regs *ctx) {
    //实例化一个自定义结构体
    struct data_t data = {};

    //声明 BPF 程序需要用到的数据结构
    struct task_struct *task = NULL;
    struct sched_entity *my_q;
    struct timespec tt; 
    //get_time_idle函数的绝对地址
    //u64 add = 0xffffffffb2f06090; 
    
    //int clocks_per_sec;


    data.pid = bpf_get_current_pid_tgid();
    if(data.pid == 1) 
    {
        //获取进程描述符
        task = (struct task_struct *)bpf_get_current_task();

        //data.ts = bpf_ktime_get_ns();
        //获取进程管理部分数据

        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        
        //clocks_per_sec = sysconf(_SC_CLK_TCK);
        data.utime = task->utime;
        data.stime = task->stime; 
               
        
        //获取进程调度实体
        my_q = (struct sched_entity *)&task->se;
        data.sum_exec_runtime = my_q->sum_exec_runtime;
        data.vruntime = my_q->vruntime;
        
        //调用get_idle_time(0)，会出现段错误
        //data.cputime = ((get_time_idle_type)add)(0);
        
        //传送数据到用户空间
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
"""


# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="schedule", fn_name="process_time")

'''
#定义一个RIGISTRY，用来将多个指标保存在一起返回
app = Flask(__name__)
REGISTRY = CollectorRegistry(auto_describe=False)
proce_usr_time_tick = Gauge('proce_usr_time_tick','the numbers of process in user space',registry=REGISTRY)
proce_sys_time_tick = Gauge('proce_sys_time_tick','the numbers of process in kernel space',registry=REGISTRY)

#下面是附着在perf_output流上的函数，在它里面我们更新gauge对象的值
def print_event(process_time, data, size):

       event = b["events"].event(data)
       proce_usr_time_tick.set(event.utime) 
       proce_sys_time_tick.set(event.stime)
    
#这个是flask的路由函数，在里面用了bcc perf_output，看结果能用，后面再优化
@app.route('/metrics')
def res():
    b["events"].open_perf_buffer(print_event)
    b.perf_buffer_poll()
    return Response(prometheus_client.generate_latest(REGISTRY),mimetype='text/plain')

if __name__ == "__main__":
    app.run(host = '0.0.0.0')
'''


def create(reg):
    print("%s is import..." % __name__)

    #metrics = Gauge('process_1_utime','task2Metric',registry=reg)
    metrics = Gauge('process1Utime','task2Metric')
            
    def print_event(process_time, data, size):
        event = b["events"].event(data)
        metrics.set(event.utime)
    b["events"].open_perf_buffer(print_event)

    return b





