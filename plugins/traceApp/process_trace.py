#!/usr/bin/env python
# coding=utf-8
# author: wingchiLeung

# process_trace.py  Trace process fork and exit via  wake_up_new_task and exit_signals syscalls


# USAGE: process_trace.py  $appName
# example: process_trace.py firefox

from bcc import BPF
import psutil
import sys
import buffer


def get_pid_byName():
    if len(sys.argv) > 1:
        name = (sys.argv[1])
    else:
        print("please enter app's name..")
        sys.exit()
    pids = psutil.process_iter()

    for pid in pids:
        if pid.name() == name:
            print("you are tracing pid: %d" % pid.pid)
            return pid.pid

    print("there is no name call %s! " % name)
    sys.exit()


pid = get_pid_byName()

# define BPF program
bpf_text = """
    # include <linux/sched.h>
    # include <linux/init_task.h>
    # include <linux/list.h>
    # include <linux/kernel.h>

    
    
    struct data_t {
        u32 pid;
        u32 tgid ;
      
        u32 bcc_pid;
        u32 bcc_tgid;
        char comm[TASK_COMM_LEN] ;
    };

    //创建一个bpf表叫做events
    BPF_PERF_OUTPUT(forks);
    BPF_PERF_OUTPUT(exits);

    int exiting(struct pt_regs *ctx,struct task_struct *tsk){
        struct data_t data = {} ;
        UID_FILTER
        struct task_struct *pos=tsk->parent;
        int flag=0;

         for(int i=0;i<3;i++){
            if(pos->pid==1 ){
                return 0;
            }
            if(pos->pid==PID||pos->tgid==PID){
                data.bcc_pid = pos->pid;
                data.bcc_tgid= pos->tgid;
                flag=1;
                break;
            }
            pos=pos->parent;
        }
        if(flag==0) return 0 ;
        data.pid = tsk->pid ;
        data.tgid = tsk->tgid ;
        
        data.bcc_pid = PID;
        
        bpf_get_current_comm(&data.comm, sizeof(data.comm)) ;
    
        exits.perf_submit(ctx,&data,sizeof(data)) ;

        return 0;
    }

    int do_trace(struct pt_regs *ctx){
        struct data_t data = {} ;
        
        UID_FILTER
        struct task_struct *tsk = PT_REGS_RC(ctx);
        struct task_struct *pos=tsk->parent ;
        
        int flag=0;
        
        
        for(int i=0;i<3;i++){
            if(pos->pid==1 ){
                return 0;
            }
            if(pos->pid==PID||pos->tgid==PID){
                data.bcc_pid = pos->pid;
                data.bcc_tgid= pos->tgid;
                flag=1;
                break;
            }
            pos=pos->parent;
        }
        if(flag==0) return 0;
        data.pid = tsk->pid ; 
        data.tgid = tsk->tgid ;

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
b.attach_kretprobe(event="copy_process", fn_name="do_trace")
b.attach_kprobe(event="exit_signals", fn_name="exiting")


# print("%-18s %-16s %-6s %s %9s %13s" %
#       ("COUNT", "COMM", "PID", "TGID", "B_PID", "B_TGID"))

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
    # print("%-18.9f %-16s %-6d %s %9s %13s" % (fork_count, event.comm, event.pid,
    #                                           event.tgid, event.bcc_pid, event.bcc_tgid))


def exit_event(cpu, data, size):
    global exit_count
    exit_count += 1
    event = b["exits"].event(data)
    buffer.delete(event.pid)
# debug: print the result to file
    with open('exits.txt', 'a') as f2:
        f2.writelines(str(event.pid))
        f2.write("\n")
    # print("%-18.9f %-16s %-6d %s %9s %13s" % (exit_count, event.comm, event.pid,
    #                                           event.tgid, event.bcc_pid, event.bcc_tgid))


b["forks"].open_perf_buffer(fork_event)
b["exits"].open_perf_buffer(exit_event)

# loop with callback to print_event
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:

        buffer.travel()
        exit()
