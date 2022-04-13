#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#tcpwin: Trace TCP Congestion Control
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
#include <linux/skbuff.h>


struct cwnd_data{
    u32 pid;
    u32 tgid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u32 state;
    u32 snd_cwnd;
    u32 snd_ssthresh;
    u32 sndbuf;
    u32 sk_wmem_queued;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(cwnd_events);


int trace_tcp_rcv_established(struct pt_regs *ctx,struct sock *sk)

{   
    u8 protocol;
    bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&sk->sk_gso_max_segs) - 3);
    if(protocol != IPPROTO_TCP)
       return 0;
    struct cwnd_data data4;
    struct task_struct *task=(struct task_struct *)bpf_get_current_task();
    struct task_struct *leader=task->group_leader;
    struct tcp_sock *tp =(struct tcp_sock *)sk;
    
    u32 snd_cwnd=tp->snd_cwnd;
    u32 snd_ssthresh=tp->snd_ssthresh;
    u32 sndbuf=sk->sk_sndbuf;
    u32 sk_wmem_queued=sk->sk_wmem_queued;

    u32 pid = task->pid;
    u32 tgid = task->tgid;
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    u32 state = sk->sk_state;
    u32 saddr = sk->__sk_common.skc_rcv_saddr;
    u32 daddr = sk->__sk_common.skc_daddr;
    
    data4.tgid=tgid; 
    data4.pid = pid;
    data4.saddr = saddr;
    data4.daddr = daddr;
    data4.lport = lport;
    data4.dport = ntohs(dport);
    data4.state = state;
    data4.snd_cwnd=snd_cwnd;
    data4.snd_ssthresh=snd_ssthresh;
    data4.sndbuf=sndbuf;
    data4.sk_wmem_queued=sk_wmem_queued;
    bpf_probe_read_kernel(&data4.comm,TASK_COMM_LEN,&(leader->comm));
    cwnd_events.perf_submit(ctx, &data4, sizeof(data4));
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
def print_cwnd_events(cpu, data, size):
    event = b["cwnd_events"].event(data)
    state=tcpstate2str(event.state).encode()
    dest_ip = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    saddr = inet_ntop(AF_INET, pack("I", event.saddr)).encode()
    print("%-6d %-6d %-12.12s %-16s %-6d %-16s %-6d %-12.12s %-10d %-10d %-10d %-10d" % (event.pid,
            event.tgid,str(event.comm,encoding='UTF-8'),
            str(saddr,encoding='UTF-8'), event.lport,
            str(dest_ip,encoding='UTF-8'), event.dport,str(state,encoding='UTF-8'),event.snd_cwnd,event.snd_ssthresh,event.sndbuf,event.sk_wmem_queued))
# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_rcv_established", fn_name="trace_tcp_rcv_established")


print("Tracing connect ... Hit Ctrl-C to end")

print("%-6s %-6s %-12s %-16s %-6s %-16s %-6s %-12s %-10s %-10s %-10s %-10s" % ("PID", "TGID", "Main_COMM", "SADDR",
            "LPORT","DADDR", "DPORT", "STATE", "CWND", "SSTHRESH", "SK_BUFF", "WMEM_QUEUED"))
    
    # read events
b["cwnd_events"].open_perf_buffer(print_cwnd_events)

while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
