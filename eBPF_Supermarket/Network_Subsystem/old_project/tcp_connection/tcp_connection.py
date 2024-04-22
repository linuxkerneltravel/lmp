from __future__ import print_function

import os
import sys

sys.path.append(os.path.realpath("../visual"))

import argparse
from socket import AF_INET, AF_INET6, inet_ntop
from struct import pack
from time import strftime

from bcc import BPF



############## arguments #################
parser = argparse.ArgumentParser(description="Trace TCP connections",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-P", "--pid", help="trace this PID only")
parser.add_argument("-p", "--port", help="comma-separated list of local ports to trace")
parser.add_argument("-r", "--direction", help="trace this direction only") # 'accept' or 'connect'
parser.add_argument("-c", "--count", type=int, default=99999999, help="count of outputs")
parser.add_argument("--print", action="store_true", help="print results to terminal")
parser.add_argument("--visual", action="store_true", help="enable visualization with influxdb-grafana")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true", help="trace IPv6 family only")
args = parser.parse_args()

bpf_text = open('tcp_connection.c').read()

# -------- code substitutions --------
if args.pid:
    bpf_text = bpf_text.replace('##FILTER_PID##',
        'if (pid != %s) { return 0; }' % args.pid)

if args.port:
    sports = [int(sport) for sport in args.port.split(',')]
    sports_if = ' && '.join(['sport != %d' % sport for sport in sports])
    bpf_text = bpf_text.replace('##FILTER_PORT##', 'if (%s) { return 0; }' % sports_if)   

if args.ipv4:
    bpf_text = bpf_text.replace('##FILTER_FAMILY##', 'if (family != AF_INET) { return 0; }')
    bpf_text = bpf_text.replace('##FILTER_FAMILY4##', 'return 0;')
elif args.ipv6:
    bpf_text = bpf_text.replace('##FILTER_FAMILY##', 'if (family != AF_INET6) { return 0; }')
    bpf_text = bpf_text.replace('##FILTER_FAMILY6##', 'return 0;')

if args.direction:
    dir = args.direction
    if(dir=='accept'):
        bpf_text = bpf_text.replace('##FILTER_DIRECTION##', 'return 0;')
    if(dir=='connect'):
        bpf_text = bpf_text.replace('##FILTER_DIRECTION##', 'return 0;')

if args.visual:
    from utils import export_tcp_connection

bpf_text = bpf_text.replace('##FILTER_PID##', '')
bpf_text = bpf_text.replace('##FILTER_PORT##', '')
bpf_text = bpf_text.replace('##FILTER_FAMILY##', '')
bpf_text = bpf_text.replace('##FILTER_FAMILY4##', '')
bpf_text = bpf_text.replace('##FILTER_FAMILY6##', '')
bpf_text = bpf_text.replace('##FILTER_DIRECTION##', '')


################## printer for results ###################
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    if args.print:
        print("%-9s %-7d %-15.15s %-2d %-42s %-42s %10s" % (
            strftime("%H:%M:%S"),
            event.pid, event.task.decode(), event.ip,
            "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.sport),
            "%s:%d" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
            "accept" if event.direction==0 else "connect"))
    if args.visual:
        export_tcp_connection(event, 4)

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    if args.print:
        print("%-9s %-7d %-15.15s %-2d %-42s %-42s %10s" % (
            strftime("%H:%M:%S"),
            event.pid, event.task.decode(), event.ip,
            "%s:%d" % (inet_ntop(AF_INET6, event.saddr), event.sport),
            "%s:%d" % (inet_ntop(AF_INET6, event.daddr), event.dport),
            "accept" if event.direction==0 else "connect"))
    if args.visual:
        export_tcp_connection(event, 6)
        

################## start tracing ##################
b = BPF(text=bpf_text)

if args.print:
    # -------- print header --------
    print("%-9s %-7s %-15s %-2s %-42s %-42s %10s" % 
        ("TIME", "PID", "TASK", "IP", "SADDR:SPORT", "DADDR:DPORT", "DIRECTION"))

# -------- read events --------
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)

count = 0

while 1:

    count += 1
    if count > args.count:
        break

    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

