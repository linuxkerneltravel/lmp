#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
prog="""
#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
BPF_HASH(count, int, int);


int count_kprobe(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, int segs) {
    int key =1;
    int zero = 0;
    int *val, tmp;
    val = count.lookup_or_try_init(&key, &zero);
    if (val)
        *val += segs;
    bpf_probe_read(&tmp, sizeof(int), val);
    bpf_trace_printk("kprobe,%d\\n", tmp);
    return 0;
}


int count_tracepoint(void *args) {
    int key = 0;
    int zero = 0;
    int *val, tmp;
    val = count.lookup_or_try_init(&key, &zero);
    if (val)
        *val += 1;
    bpf_probe_read(&tmp, sizeof(int), val);
    bpf_trace_printk("tracepoint,%d\\n", tmp);
    return 0;
}
"""
b = BPF(text=prog)
b.attach_kprobe(event="tcp_retransmit_skb", fn_name="count_kprobe")
b.attach_tracepoint(tp="tcp:tcp_retransmit_skb", fn_name="count_tracepoint")
# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "message"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
