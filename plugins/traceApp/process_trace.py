#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# author: wingchi-Leung

# process_trace.py  Trace process fork and exit via  kernel_clone and do_exit syscalls


from bcc import BPF
import psutil
import argparse
import buffer
import os
from _thread import interrupt_main


# 参数给定pid或名称 ， 退出时间默认为9999秒
parser = argparse.ArgumentParser(
    description="trace all process fork and exit of a given app")
parser.add_argument("-p", "--pid", type=int, help="application's pid")
parser.add_argument("--name", help="application's name")
parser.add_argument("-t", "--time", type=int, help="run time", default=9999)

args = parser.parse_args()

pid = 0
if args.name:
    pids = psutil.process_iter()

    for process_info in pids:
        if process_info.name() == args.name:
            print(process_info.pid)
            pid = (process_info.pid)
else:
    pid = int(args.pid)

print("you are tracing pid: %d" % pid)
os.system("pstree -p "+str(pid)+" > befores.txt")


# define BPF program
bpf_text = """
    # include <linux/sched.h>
    # include <linux/init_task.h>
    # include <linux/list.h>
    # include <linux/kernel.h>

    enum event_type{
        EVENT_FORK,
        EVENT_EXIT,
    };

    struct data_t {
        u32 pid;
        u32 tgid ;
        u32 uid;
        enum event_type type ;
        char comm[TASK_COMM_LEN] ;
    };
    // 保存进程号,key(u32) : data进程信息
    BPF_HASH(forked,u32,struct data_t);
    BPF_PERF_OUTPUT(events);


    int exiting(struct pt_regs *ctx,long code){
        struct data_t data = {} ;
        struct data_t *value;
        int flag=0;
        UID_FILTER
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct task_struct *pos =task;
        u32 pid = task->pid ;
        //先查表
        value =  forked.lookup(&pid) ; 
        if( value!= NULL) {
            value->type=EVENT_EXIT;
            events.perf_submit(ctx,value,sizeof(data)) ;
            forked.delete(&pid);
            return 0 ;
        } 
        //查不到再遍历，捕获的是程序启动前就存在的进程
        for (int i=0; pos!=NULL && i<10;pos=pos->parent,i++){
            if(pos->tgid==1) {
                return 0 ;
            }
            if(pos->pid==PID||pos->tgid==PID){
                flag=1 ;
                break ;
            }
        }
        if(flag==0) return 0 ;
        forked.delete(&pid);
        data.pid = pid ;
        data.tgid = task->tgid ;
        data.type = EVENT_EXIT;
        data.uid  = bpf_get_current_uid_gid() & 0xffffffff;
        bpf_get_current_comm(&data.comm, sizeof(data.comm)) ;
        events.perf_submit(ctx,&data,sizeof(data)) ;
        return 0;
    }

    int forking(struct pt_regs *ctx,struct kernel_clone_args *args){
        struct data_t data = {} ;
        pid_t pid = PT_REGS_RC(ctx) ;
        UID_FILTER
        int flag=0;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct task_struct *pos = task ;

        for (int i=0; pos!=NULL && i<10;pos=pos->parent,i++){
            if(pos->tgid==1) {
                return 0 ;
            }
            if(pos->pid==PID||pos->tgid==PID){
                flag=1 ;
                break ;
            }
        }
        if(flag==0) return 0 ;
        
        data.pid = pid ;
        data.tgid = bpf_get_current_pid_tgid()>>32 ;
        data.type=EVENT_FORK;
        data.uid= bpf_get_current_uid_gid() & 0xffffffff;
        bpf_get_current_comm(&data.comm, sizeof(data.comm)) ;
        forked.insert(&pid,&data) ;
        events.perf_submit(ctx,&data,sizeof(data)) ;

        return 0;
    }

"""

if pid:
    bpf_text = bpf_text.replace("UID_FILTER", 'pid_t PID=%d;' % pid)
else:
    bpf_text = bpf_text.replace("UID_FILTER", 'pid_t PID=0;')

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kretprobe(event="kernel_clone", fn_name="forking")

b.attach_kprobe(event="do_exit", fn_name="exiting")


print("hit ctrl-C to print result ...\n")


forked = b.get_table("forked")

# 因为一些原因，此枚举类型的数值不能改变


class EventType (object):
    EVENT_FORK = 0
    EVENT_EXIT = 1


def print_event(cpu, data, size):
    event = b["events"].event(data)
    exit_count = 0
    fork_count = 0
    if event.type == EventType.EVENT_FORK:
        fork_count += 1

        buffer.add(event.pid, event.comm)
        with open('fork.txt', 'a') as f1:
            f1.writelines(str(event.pid))
            f1.write("\n")
    else:
        exit_count += 1
        res = buffer.delete(event.pid)

        with open('exit.txt', 'a') as f2:
            f2.writelines(str(event.pid))
            f2.write("\n")


b["events"].open_perf_buffer(print_event)

# loop with callback to print_event
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        forked.clear()
        buffer.travel()
        id = str(pid)
        os.system("pstree -p "+str(pid)+" > afters.txt")
        exit()
