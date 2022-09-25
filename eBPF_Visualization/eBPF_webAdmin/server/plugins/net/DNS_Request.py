#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from __future__ import print_function
from bcc import BPF
import dnslib


dns_bpf_text = """
#include <net/inet_sock.h>

struct dns_data_t {
   u8  pkt[200];
};

BPF_PERF_OUTPUT(dns_events);

int trace_udp_sendmsg(struct pt_regs *ctx)
{
        struct dns_data_t data ={};
        struct msghdr *msghdr = (struct msghdr *)PT_REGS_PARM2(ctx);
        struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
        struct inet_sock *is = inet_sk(sk);
        
        if (msghdr == 0)
            return 0;
        if (is->inet_dport == 13568) {
            void *iovbase = msghdr->msg_iter.iov->iov_base;
            if(iovbase == 0)
             return 0;
            bpf_probe_read(data.pkt,200, iovbase);
            dns_events.perf_submit(ctx, &data, sizeof(data));
        }
        return 0;
}
"""

b = BPF(text=dns_bpf_text)
b.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")


def print_ipv4_event(cpu, data, size):
     event = b["dns_events"].event(data)
     payload = event.pkt[:size]
     dnspkt = dnslib.DNSRecord.parse(payload)
     print(dnspkt)

b["dns_events"].open_perf_buffer(print_ipv4_event)

while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
