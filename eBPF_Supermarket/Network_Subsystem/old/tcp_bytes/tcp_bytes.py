from __future__ import print_function

import os
import sys

sys.path.append(os.path.realpath("../visual"))

import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep, localtime, asctime, time

from bcc import BPF
from collections import namedtuple, defaultdict



############## arguments #################
parser = argparse.ArgumentParser(description="Summarize TCP send/recv throughput by host",
    formatter_class=argparse.RawDescriptionHelpFormatter,)
parser.add_argument("-P", "--pid", help="trace this PID only")
parser.add_argument("-i", "--interval", type=float, default=1)
parser.add_argument("-c", "--count", type=int, default=99999999, help="count of outputs")
parser.add_argument("--print", action="store_true", help="print results to terminal")
parser.add_argument("--visual", action="store_true", help="enable visualization with influxdb-grafana")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true", help="trace IPv6 family only")
args = parser.parse_args()

print_interval = args.interval + 0.0
if print_interval <= 0:
    print ("print interval must stricly positive")
    exit()

bpf_text = open('tcp_bytes.c').read()

# -------- code substitutions --------
if args.pid:
    bpf_text = bpf_text.replace('##FILTER_PID##', 'if (pid != %s) { return 0; }' % args.pid)
    
if args.ipv4:
    bpf_text = bpf_text.replace('##FILTER_FAMILY##', 'if (family != AF_INET) { return 0; }')
elif args.ipv6:
    bpf_text = bpf_text.replace('##FILTER_FAMILY##', 'if (family != AF_INET6) { return 0; }')

if args.visual:
    from utils import export_tcp_bytes

bpf_text = bpf_text.replace('##FILTER_PID##', '')
bpf_text = bpf_text.replace('##FILTER_FAMILY##', '')


################## printer for results ###################
TCPSessionKey = namedtuple('TCPSession', ['pid', 'task', 'saddr', 'sport', 'daddr', 'dport'])

def get_ipv4_session_key(k):
    return TCPSessionKey(pid=k.pid, task=k.task, saddr=inet_ntop(AF_INET, pack("I", k.saddr)),
                         sport=k.sport, daddr=inet_ntop(AF_INET, pack("I", k.daddr)), dport=k.dport)

def get_ipv6_session_key(k):
    return TCPSessionKey(pid=k.pid, task=k.task, saddr=inet_ntop(AF_INET6, k.saddr),
                         sport=k.sport, daddr=inet_ntop(AF_INET6, k.daddr), dport=k.dport)


################## start tracing ##################
b = BPF(text=bpf_text)

ipv4_send = b["ipv4_send"]
ipv4_recv = b["ipv4_recv"]
ipv6_send = b["ipv6_send"]
ipv6_recv = b["ipv6_recv"]

count = 0

while 1:

    count += 1
    if count > args.count:
        break

    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exit()
    
    if args.print:
    # -------- print header --------
        print("-"*60)
        print(asctime(localtime(time())))

    # -------- IPv4: build dict of all seen keys --------
    ipv4_throughput = defaultdict(lambda: [0, 0])
    for k, v in ipv4_send.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][0] = v.value
    ipv4_send.clear()

    for k, v in ipv4_recv.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][1] = v.value
    ipv4_recv.clear()

    # -------- IPv4: output --------
    if ipv4_throughput and (args.print or args.visual):
        if args.print:
            print("%-7s %-15s %-22s %-22s %6s %6s" % 
                ("PID", "TASK", "SADDR:SPORT", "DADDR:DPORT", "RX_KB", "TX_KB"))

        for k, (send_bytes, recv_bytes) in sorted(ipv4_throughput.items(),
                                                key=lambda kv: sum(kv[1]),
                                                reverse=True):
            if args.print:                             
                print("%-7d %-15s %-22s %-22s %6d %6d" % ( 
                    k.pid, k.task.decode(),
                    "%s:%d" % (k.saddr, k.sport), "%s:%d" % (k.daddr, k.dport),
                    int(recv_bytes/1024), int(send_bytes/1024)))
            if args.visual:
                export_tcp_bytes(k, send_bytes, recv_bytes)

    # -------- IPv6: build dict of all seen keys --------
    ipv6_throughput = defaultdict(lambda: [0, 0])
    for k, v in ipv6_send.items():
        key = get_ipv6_session_key(k)
        ipv6_throughput[key][0] = v.value
    ipv6_send.clear()

    for k, v in ipv6_recv.items():
        key = get_ipv6_session_key(k)
        ipv6_throughput[key][1] = v.value
    ipv6_recv.clear()

    # -------- IPv6: output --------
    if ipv6_throughput and (args.print or args.visual):
        if args.print:
            print("\n%-7s %-15s %-42s %-42s %6s %6s" % 
                ("PID", "TASK", "SADDR6:SPORT", "DADDR6:DPORT", "RX_KB", "TX_KB"))

        for k, (send_bytes, recv_bytes) in sorted(ipv6_throughput.items(),
                                                key=lambda kv: sum(kv[1]),
                                                reverse=True):
            if args.print: 
                print("%-7d %-15s %-42s %-42s %6d %6d" % (
                    k.pid, k.task.decode(),
                    "%s:%d" % (k.saddr, k.sport), "%s:%d" % (k.daddr, k.dport),
                    int(recv_bytes / 1024), int(send_bytes / 1024)))
            if args.visual:
                export_tcp_bytes(k, send_bytes, recv_bytes)

