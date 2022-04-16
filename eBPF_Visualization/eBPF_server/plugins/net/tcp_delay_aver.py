#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# fullc_connect:    Trace TCP connect fully
#Author: Dongxu
 

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
from time import sleep
from datetime import datetime


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <linux/pid.h>

struct info{
    struct task_struct *task;
    u64 start_us;
};
BPF_HASH(currsock, struct sock *, struct info);
// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u32 pid;
    u32 tgid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    u32 state;
    u64 delta_us;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);


int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{   

    struct info info;
    info.start_us = bpf_ktime_get_ns();
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    info.task = t;
    currsock.update(&sk,&info);
    
    return 0;
};

 int trace_tcp_finish_connect_entry(struct pt_regs *ctx,struct sock *sk)
{
    short ipver=4;
    struct info *t_info = currsock.lookup(&sk);
    if (t_info == 0) {
        return 0;   
    }
    struct info *info = t_info;
    struct task_struct *task=info->task;
    u64 end_us = bpf_ktime_get_ns();
    u64 delta_us = (end_us-info->start_us)/1000;
    struct sock *skp = sk;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    u32 state = skp->sk_state;
    struct task_struct *leader=task->group_leader;
    u32 pid = task->pid;
    u32 tgid = task->tgid;
    if (ipver == 4) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
               data4.saddr = skp->__sk_common.skc_rcv_saddr;
               data4.daddr = skp->__sk_common.skc_daddr;
               data4.lport = lport;
               data4.dport = ntohs(dport);
               data4.state = state-1;
               data4.tgid=tgid;
               data4.delta_us = delta_us;
               bpf_probe_read_kernel(&data4.task,TASK_COMM_LEN,&(leader->comm));
               ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } 
    
    currsock.delete(&sk);
    return 0;
}
"""
count = 0
time = 0
def tcpstate2str(state):
    # from include/net/tcp_states.h:
    tcpstate = {
        1: "ESTABLISHED",
        2: "SYN_SENT",
        3: "SYN_RECV",
        4: "FIN_WAIT1",
        5: "FIN_WAIT2",
        6: "TIME_WAIT",
        7: "CLOSE",
        8: "CLOSE_WAIT",
        9: "LAST_ACK",
        10: "LISTEN",
        11: "CLOSING",
        12: "NEW_SYN_RECV",
    }

    if state in tcpstate:
        return tcpstate[state]
    else:
        return str(state)


# process event
def print_ipv4_event(cpu, data, size):
    global count
    global time
    event = b["ipv4_events"].event(data)
    state=tcpstate2str(event.state).encode()
    dest_ip = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    delta_us=inet_ntop(AF_INET, pack("I", event.delta_us)).encode()
    count=count+1
    time += event.delta_us
    aver = time/count
    print("%-6d %-6d %-12.12s %-2d %-16s %-6d %-16s %-6d %-12.12s %-12.12s %-12.12s" %(event.pid,
            event.tgid,str(event.task,encoding='UTF-8'), event.ip,
          str(inet_ntop(AF_INET, pack("I", event.saddr)).encode(),encoding='UTF-8'), event.lport,
           str(dest_ip,encoding='UTF-8'), event.dport,str(state,encoding='UTF-8'),event.delta_us,aver))
    #print("%-6d %-6d %-12.12s %-2d %-16s %-6d %-16s %-6d %-12.12s %-12.12s %-12.12s"str(dest_ip,encoding='UTF-8'),event.dport,event.delta_us,aver)


# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")

b.attach_kprobe(event="tcp_finish_connect", fn_name="trace_tcp_finish_connect_entry")

print("Tracing connect ... Hit Ctrl-C to end")

print("%-6s %-6s %-12s %-2s %-16s %-6s %-16s %-6s %-12s %-12.12s %-12.12s" % ("PID", "TGID", "Main_COMM", "IP", "SADDR",
            "LPORT","DADDR", "DPORT", "STATE", "TIME", "Current_AVER"))
    
    # read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)

while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

