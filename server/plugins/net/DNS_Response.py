#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from __future__ import print_function
from bcc import BPF
from time import sleep
from datetime import datetime
import dnslib


dns_bpf_text = """
#include <net/inet_sock.h>

#define MAX_PKT 512
struct dns_data_t {
    u8  pkt[MAX_PKT];
};

BPF_PERF_OUTPUT(dns_events);

// store msghdr pointer captured on syscall entry to parse on syscall return
BPF_HASH(tbl_udp_msg_hdr, u64, struct msghdr *);

// single element per-cpu array to hold the current event off the stack
BPF_PERCPU_ARRAY(dns_data,struct dns_data_t,1);

int trace_udp_recvmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct inet_sock *is = inet_sk(sk);

    // only grab port 53 packets, 13568 is ntohs(53)
    if (is->inet_dport == 13568) {
        struct msghdr *msghdr = (struct msghdr *)PT_REGS_PARM2(ctx);
        tbl_udp_msg_hdr.update(&pid_tgid, &msghdr);
    }
    return 0;
}

int trace_udp_ret_recvmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 zero = 0;
    struct msghdr **msgpp = tbl_udp_msg_hdr.lookup(&pid_tgid);
    if (msgpp == 0)
        return 0;

    struct msghdr *msghdr = (struct msghdr *)*msgpp;
    if (msghdr->msg_iter.type != ITER_IOVEC)
        goto delete_and_return;

    int copied = (int)PT_REGS_RC(ctx);
    if (copied < 0)
        goto delete_and_return;
    size_t buflen = (size_t)copied;

    if (buflen > msghdr->msg_iter.iov->iov_len)
        goto delete_and_return;

    if (buflen > MAX_PKT)
        buflen = MAX_PKT;

    struct dns_data_t *data = dns_data.lookup(&zero);
    if (!data) // this should never happen, just making the verifier happy
        return 0;

    void *iovbase = msghdr->msg_iter.iov->iov_base;
    bpf_probe_read(data->pkt, buflen, iovbase);
    dns_events.perf_submit(ctx, data, buflen);

delete_and_return:
    tbl_udp_msg_hdr.delete(&pid_tgid);
    return 0;
}
"""

# process event
def save_dns(cpu, data, size):
    event = b["dns_events"].event(data)
    payload = event.pkt[:size]

    dnspkt = dnslib.DNSRecord.parse(payload)

    if dnspkt.header.qr != 1:
        return
    if dnspkt.header.q != 1:
        return
    if dnspkt.header.a == 0 and dnspkt.header.aa == 0:
        return
    question = ("%s" % dnspkt.q.qname)[:-1].encode('utf-8')
    for answer in dnspkt.rr:
        # skip all but A and AAAA records
        if answer.rtype == 1 or answer.rtype == 28:
            sleep(1)
            print(str(answer.rdata).encode('utf-8'),question,datetime.now())

b = BPF(text=dns_bpf_text)
b.attach_kprobe(event="udp_recvmsg", fn_name="trace_udp_recvmsg")
b.attach_kretprobe(event="udp_recvmsg", fn_name="trace_udp_ret_recvmsg")

print("Tracing connect ... Hit Ctrl-C to end")   

b["dns_events"].open_perf_buffer(save_dns)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
