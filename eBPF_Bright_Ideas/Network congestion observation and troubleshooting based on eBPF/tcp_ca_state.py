#!/usr/bin/python
# tcp_ca_state:    Trace TCP congestion state
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
#include <net/tcp.h>
#include <linux/tcp.h>
#include <net/tcp_states.h>
#include <linux/skbuff.h>

// separate data structs for ipv4 and ipv6
struct ca_data_t {
    u32 pid;
    u32 tgid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    u8 oldca_state;
    u8 newca_state
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ca_events);
BPF_HASH(currca, struct sock *, u8 ca_state);

int trace_tcp_fastretrans_alert_entry(struct pt_regs *ctx,struct sock *sk)
{
    u8 ca_state;
    struct inet_connection_sock *icsk = inet_csk(sk);
    ca_state=icsk->icsk_ca_state;
    currca.update(&sk,&ca_state);
    return 0;

}


 int trace_tcp_fastretrans_alert_return(struct pt_regs *ctx,struct sock *sk)
{
    u8 nowca_state;
    u8 *oldca_state;
    oldca_state= currsock.lookup(&sk);
    if(oldca_state==0){
        return 0;
    }
    struct inet_connection_sock *icsk = inet_csk(sk);
    nowca_state=icsk->icsk_ca_state;

    struct task_struct *task=(struct task_struct *)bpf_get_current_task();
    struct sock *skp = sk;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    u32 state = skp->sk_state;
    struct task_struct *leader=task->group_leader;
    u32 pid = task->pid;
    u32 tgid = task->tgid;
        struct ca_data_t ca = {.pid = pid, .ip = ipver};
               ca.saddr = skp->__sk_common.skc_rcv_saddr;
               ca.daddr = skp->__sk_common.skc_daddr;
               ca.lport = lport;
               ca.dport = ntohs(dport);
               ca.oldca_state = *oldca_state;
               ca.newca_state = nowca_state;
               ca.tgid=tgid;
               bpf_probe_read_kernel(&ca.task,TASK_COMM_LEN,&(leader->comm));
               ipv4_events.perf_submit(ctx, &ca, sizeof(ca));
    
    currca.delete(&sk);
    return 0;
}
"""


def castate2str(state):
    castate = {
        0: "TCP_CA_Open",
        1: "TCP_CA_Disorder",
        2: "TCP_CA_CWR",
        3: "TCP_CA_Recovery",
        4: "TCP_CA_Loss",
    }

    if state in castate:
        return castate[state]
    else:
        return str(state)



# process event
def print_ca_event(cpu, data, size):
    event = b["ca_events"].event(data)
    oldca_state=tcpstate2str(event.oldca_state).encode();
    newca_state=tcpstate2str(event.newca_state).encode();
    dest_ip = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    printb(b"%-6d %-6d %-12.12s %-2d %-16s %-6d %-16s %-6d %-12.12s %-12.12s" % (event.pid,
        event.tgid,event.task, event.ip,inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
        event.lport, dest_ip, event.dport,oldca_state,newca_state))
# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_fastretrans_alert", fn_name="trace_tcp_fastretrans_alert_entry")

b.attach_kretprobe(event="tcp_fastretrans_alert", fn_name="trace_tcp_fastretrans_alert_return")

print("Tracing connect ... Hit Ctrl-C to end")

print("%-6s %-6s %-12s %-2s %-16s %-6s %-16s %-6s %-12s %-12s" % ("PID", "TGID", "Main_COMM", "IP", "SADDR",
            "LPORT","DADDR", "DPORT", "Old_CA", "New_CA"))
    
    # read events
b["ca_events"].open_perf_buffer(print_ca_event)

while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()