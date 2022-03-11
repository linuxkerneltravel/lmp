#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#Tace detail about TCP packet segments
#Author:XU Dong
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
#include <net/tcp.h>
#include <linux/tcp.h>
#include <net/tcp_states.h>

// separate data structs for ipv and ipv6
struct ipv4_data{
    u32 pid;
    u32 end_seq;
    u32 start_seq;
    u32 tgid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u32 state;
    u64 start_us;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);


int trace___tcp_transmit_skb_entry(struct pt_regs *ctx,struct sock *sk, struct sk_buff *skb)
{   
    u8 protocol;
    bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&sk->sk_gso_max_segs) - 3);
    if(protocol != IPPROTO_TCP)
       return 0;
    struct ipv4_data data4;
    struct task_struct *task=(struct task_struct *)bpf_get_current_task();
    struct task_struct *leader=task->group_leader;
    struct tcp_skb_cb *tcb=TCP_SKB_CB(skb);
    u32 start_seq=tcb->seq;
    u32 end_seq=tcb->end_seq;
    if(start_seq==0 || end_seq ==0 )
    return 0;
    u64 start_us = bpf_ktime_get_ns();
    u32 pid = task->pid;
    u32 tgid = task->tgid;
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    u32 state = sk->sk_state;
    u32 saddr = sk->__sk_common.skc_rcv_saddr;
    u32 daddr = sk->__sk_common.skc_daddr;
    if(saddr == daddr || lport==22)
        return 0;
    if(pid == 0)
    return 0;
    
    data4.tgid=tgid; 
    data4.pid = pid;
    data4.start_us=start_us;
    data4.saddr = saddr;
    data4.daddr = daddr;
    data4.lport = lport;
    data4.dport = ntohs(dport);
    data4.state = state;
    data4.start_seq=start_seq;
    data4.end_seq=end_seq;
    bpf_probe_read_kernel(&data4.comm,TASK_COMM_LEN,&(leader->comm));
    ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    return 0;
}
"""


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
    event = b["ipv4_events"].event(data)
    state=tcpstate2str(event.state).encode()
    dest_ip = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    saddr=inet_ntop(AF_INET, pack("I", event.saddr)).encode()
    print("%-6d %-6d %-12.12s %-16s %-6d %-16s %-6d %-12.12s [%-12d%-12d)" % (event.pid,
            event.tgid,str(event.comm,encoding='UTF-8'), 
            str(saddr,encoding='UTF-8') , event.lport,
            str(dest_ip,encoding='UTF-8'), event.dport,str(state,encoding='UTF-8'),event.start_seq,event.end_seq))
# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="__tcp_transmit_skb", fn_name="trace___tcp_transmit_skb_entry")


print("Tracing connect ... Hit Ctrl-C to end")

print("%-6s %-6s %-12s %-16s %-6s %-16s %-6s %-12s %-12s %-12s" % ("PID", "TGID", "Main_COMM", "SADDR",
            "LPORT","DADDR", "DPORT", "STATE", "START_EQ", "END_EQ"))
    
    # read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)

while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
