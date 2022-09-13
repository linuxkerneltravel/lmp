from __future__ import print_function

import os
import sys

sys.path.append(os.path.realpath("../visual"))

import argparse
from socket import inet_ntop, AF_INET
from struct import pack
import ctypes as ct

from bcc import BPF
from bcc import tcp
from utils import export_tcp_flow


############## arguments #################
parser = argparse.ArgumentParser(description="Trace the TCP metrics with ACKs",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--sport", help="trace this source port only")
parser.add_argument("--dport", help="trace this destination port only")
parser.add_argument("-s", "--sample", help="Trace sampling")
parser.add_argument("-c", "--count", type=int, default=99999999, help="count of outputs")
parser.add_argument("--print", action="store_true", help="print results to terminal")
parser.add_argument("--visual", action="store_true", help="enable visualization with influxdb-grafana")
args = parser.parse_args()

bpf_text = open('tcp_flow.c').read()

# -------- code substitutions --------
if args.sport:
    bpf_text = bpf_text.replace('##FILTER_SPORT##', 'if (sport != %s) { return 0; }' % args.sport)

if args.dport:
    bpf_text = bpf_text.replace('##FILTER_DPORT##', 'if (dport != %s) { return 0; }' % args.dport)

if args.sample:
    bpf_text = bpf_text.replace('##SAMPLING##', 'if (((seq+ack) << (32-%s) >> (32-%s)) != ((0x01 << %s) - 1)) { return 0;}' % (args.sample, args.sample, args.sample))

bpf_text = bpf_text.replace('##FILTER_SPORT##', '')
bpf_text = bpf_text.replace('##FILTER_DPORT##', '')
bpf_text = bpf_text.replace('##SAMPLING##', '')


################## printer for results ###################
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("seq", ct.c_uint),
        ("ack", ct.c_uint),
        ("state", ct.c_ubyte),
        ("tcpflags", ct.c_ubyte),
        ("snd_cwnd", ct.c_uint),
        ("rcv_wnd", ct.c_uint),
        ("total_retrans", ct.c_uint),
        ("fastRe", ct.c_uint),
        ("timeout", ct.c_uint),
        ("bytes_acked", ct.c_ulonglong),
        ("bytes_received", ct.c_ulonglong),
        ("srtt", ct.c_uint),
        ("srtt_sum", ct.c_ulonglong),
        ("srtt_counter", ct.c_uint),
        ("packets_out", ct.c_uint),
        ("duration", ct.c_ulonglong),
        ("bytes_inflight", ct.c_uint),
    ]

def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    if args.print:
        print("%-22s %-22s %-10s %-10s %-8s %-8s %-12s (%-9s) %-12s" % (
            "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.sport),
            "%s:%d" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
            "%d" % (event.seq),
            "%d" % (event.ack),
            "%d" % (event.srtt >> 3),
            "%d" % (event.snd_cwnd),
            tcp.tcpstate[event.state], 
            tcp.flags2str(event.tcpflags),
            "%d" % (event.duration)
        ))
    if args.visual:
        export_tcp_flow(event, tcp.tcpstate[event.state], tcp.flags2str(event.tcpflags))


################## start tracing ##################
b = BPF(text=bpf_text)

if args.print:
    # -------- print header --------
    print("%-22s %-22s %-10s %-10s %-8s %-8s %-12s (%-9s) %-12s" % \
        ("SADDR:SPORT", "DADDR:DPORT", "SEQ", "ACK", "RTT(us)", "CWnd", "STATE", "FLAGS", "DURATION"))

# -------- read events --------
b["ipv4_events"].open_perf_buffer(print_ipv4_event)

count = 0

while 1:

    count += 1
    if count > args.count:
        break

    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
