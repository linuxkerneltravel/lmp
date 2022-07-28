#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpaccept Trace TCP accept()s.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpaccept [-h] [-T] [-t] [-p PID] [-P PORTS] [-4 | -6]
#
# This uses dynamic tracing of the kernel inet_csk_accept() socket function
# (from tcp_prot.accept), and will need to be modified to match kernel changes.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Oct-2015   Brendan Gregg   Created this.
# 14-Feb-2016      "      "     Switch to bpf_perf_output.

from __future__ import print_function
from bcc.containers import filter_by_containers
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import argparse
from bcc.utils import printb
from time import strftime

# arguments
parser = argparse.ArgumentParser(description="Trace TCP connections",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", help="trace this PID only")
parser.add_argument("-P", "--port", help="comma-separated list of local ports to trace")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true", help="trace IPv6 family only")
group.add_argument("-r", "--direction", action="store_true", help="trace this direction only")
args = parser.parse_args()

bpf_text = open('tcpconnection.c').read()

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('##FILTER_PID##',
        'if (pid != %s) { return 0; }' % args.pid)

if args.port:
    sports = [int(sport) for sport in args.port.split(',')]
    sports_if = ' && '.join(['sport != %d' % sport for sport in sports])
    bpf_text = bpf_text.replace('##FILTER_PORT##',
        'if (%s) { return 0; }' % sports_if)   

if args.ipv4:
    bpf_text = bpf_text.replace('##FILTER_FAMILY##',
        'if (family != AF_INET) { return 0; }')
    bpf_text = bpf_text.replace('##FILTER_FAMILY4##',
        'return 0;')
elif args.ipv6:
    bpf_text = bpf_text.replace('##FILTER_FAMILY##',
        'if (family != AF_INET6) { return 0; }')
    bpf_text = bpf_text.replace('##FILTER_FAMILY6##',
        'return 0;')

if args.direction:
    dir = args.direction
    if(dir=='accept'):
        bpf_text = bpf_text.replace('##FILTER_DIRECTION##',
            'return 0;')
    if(dir=='connect'):
        bpf_text = bpf_text.replace('##FILTER_DIRECTION##',
            'return 0;')

bpf_text = bpf_text.replace('##FILTER_PID##', '')
bpf_text = bpf_text.replace('##FILTER_PORT##', '')
bpf_text = bpf_text.replace('##FILTER_FAMILY##', '')
bpf_text = bpf_text.replace('##FILTER_FAMILY4##', '')
bpf_text = bpf_text.replace('##FILTER_FAMILY6##', '')
bpf_text = bpf_text.replace('##FILTER_DIRECTION##', '')

# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    printb(b"%-9s %-7d %-12.12s %-2d %-16s %-5d %-16s %-5d %10s" % (
        strftime("%H:%M:%S").encode('ascii'),
        event.pid, event.task, event.ip,
        inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
        event.dport,
        inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
        event.sport, 
        b'accept' if event.direction==0 else b'connect'))

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    printb(b"%-9s %-7d %-12.12s %-2d %-16s %-5d %-16s %-5d %10s" % (
    # print(    
        strftime("%H:%M:%S").encode('ascii'),
        event.pid, event.task, event.ip,
        inet_ntop(AF_INET6, event.daddr).encode(),
        event.dport,
        inet_ntop(AF_INET6, event.saddr).encode(),
        event.sport, 
        b'accept' if event.direction==0 else b'connect')
    )

# initialize BPF
b = BPF(text=bpf_text)

# header
print("%-9s %-7s %-12s %-2s %-16s %-5s %-16s %-5s %10s" % ("TIME", "PID", "COMM", "IP", \
    "DADDR", "DPORT", "SADDR", "SPORT", "DIRECTION"))

start_ts = 0

# b.trace_print()

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
