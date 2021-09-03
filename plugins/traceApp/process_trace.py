#!/usr/bin/env python
# coding=utf-8
# author: wingchi-Leung

# process_trace.py  Trace process fork and exit via  wake_up_new_task and exit_signals syscalls


from bcc import BPF
import psutil
import argparse
import buffer
import os

parser = argparse.ArgumentParser(
    description="trace all process fork and exit of a given app")
parser.add_argument("-p", "--pid", type=int, help="application's pid")
parser.add_argument("--name", help="application's name")

args = parser.parse_args()

pid = 0
if args.name:
    pids = psutil.process_iter()
    for process_info in pids:
        if process_info.name() == args.name:

            pid = (process_info.pid)
else:
    pid = int(args.pid)

print("you are tracing pid: %d" % pid)


# define BPF program
bpf_text = """
    # include <linux/sched.h>
    # include <linux/init_task.h>
    # include <linux/list.h>
    # include <linux/kernel.h>



    struct data_t {
        u32 pid;
        u32 tgid ;
        u32 parent_pid[5];
        u32 parent_tgid[5];
        char comm[TASK_COMM_LEN] ;
    };

    //创建一个bpf表叫做events
    BPF_PERF_OUTPUT(forks);
    BPF_PERF_OUTPUT(exits);

    int exiting(struct pt_regs *ctx,long code){
        struct data_t data = {} ;
        UID_FILTER
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct task_struct *pos =task;
        int flag=0;

        for(int i=0;i<3;i++){
            if(pos->pid==1 ){
                return 0;
            }
            data.parent_pid[i] = pos->pid ;
            data.parent_tgid[i]= pos->tgid;
            if(pos->pid==PID||pos->tgid==PID){
                flag=1;
                break;
            }
            pos=pos->parent;
        }
        if(flag==0) return 0 ;
        data.pid = task->pid ;
        data.tgid = task->tgid ;

        bpf_get_current_comm(&data.comm, sizeof(data.comm)) ;

        exits.perf_submit(ctx,&data,sizeof(data)) ;

        return 0;
    }
   
    int do_trace(struct pt_regs *ctx,struct kernel_clone_args *args){
        struct data_t data = {} ;
        pid_t pid = PT_REGS_RC(ctx) ;
        UID_FILTER
        int flag=0;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();

        for(int i=0;i<5;i++){
            if(task->pid==1 ){
                return 0;
            }
          
            if(task->pid==PID||task->tgid==PID){
                flag=1;
                break;
            }
            task=task->parent;
        }
        if(flag==0) return 0;
        data.pid = pid ;
        data.tgid = bpf_get_current_pid_tgid()>>32 ;

        bpf_get_current_comm(&data.comm, sizeof(data.comm)) ;
        forks.perf_submit(ctx,&data,sizeof(data)) ;
        return 0;
    }

"""

if pid:
    bpf_text = bpf_text.replace("UID_FILTER", 'pid_t PID=%d;' % pid)
else:
    bpf_text = bpf_text.replace("UID_FILTER", 'pid_t PID=0;')

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kretprobe(event="kernel_clone", fn_name="do_trace")
b.attach_kprobe(event="do_exit", fn_name="exiting")


print("hit ctrl-C to print result ...\n")


fork_count = 0
exit_count = 0


# process event
def fork_event(cpu, data, size):
    global fork_count
    fork_count += 1
    event = b["forks"].event(data)
    buffer.add(event.pid, event.comm)
    with open('forks.txt', 'a') as f1:
        f1.writelines(str(event.pid))
        f1.write("\n")


def exit_event(cpu, data, size):
    global exit_count
    exit_count += 1
    event = b["exits"].event(data)
    buffer.delete(event.pid)
    with open('exits.txt', 'a') as f2:
        f2.writelines(str(event.pid))
        f2.write("\n")


b["forks"].open_perf_buffer(fork_event)
b["exits"].open_perf_buffer(exit_event)

# loop with callback to print_event
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:

        buffer.travel()
        id = str(pid)

        exit()
