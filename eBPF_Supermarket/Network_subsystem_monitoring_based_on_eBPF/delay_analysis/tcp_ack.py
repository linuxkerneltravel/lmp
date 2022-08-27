from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
from bcc import tcp
import argparse
from subprocess import call
from os import kill, getpid, path
from signal import SIGKILL
import sys
# from tcptools import check_filename, valid_function_name

bpf_text = open('tcp_ack.c').read()

# args parser
parser = argparse.ArgumentParser(description="Trace the TCP metrics with ACKs",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-sp", "--sport", help="trace this source port only")
parser.add_argument("-dp", "--dport", help="trace this destination port only")
parser.add_argument("-s", "--sample", help="Trace sampling")

args = parser.parse_args()


# code substitutions
if args.sport:
    bpf_text = bpf_text.replace('##FILTER_SPORT##', 'if (sport != %s) { return 0; }' % args.sport)
if args.dport:
    bpf_text = bpf_text.replace('##FILTER_DPORT##', 'if (dport != %s) { return 0; }' % args.dport)
if args.sample:
    bpf_text = bpf_text.replace('##SAMPLING##', 'if (((seq+ack) << (32-%s) >> (32-%s)) != ((0x01 << %s) - 1)) { return 0;}' % (args.sample, args.sample, args.sample))


bpf_text = bpf_text.replace('##FILTER_SPORT##', '')
bpf_text = bpf_text.replace('##FILTER_DPORT##', '')
bpf_text = bpf_text.replace('##SAMPLING##', '')


# event data
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

# process event
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    print("%-22s -> %-22s %-10s %-10s %-8s %-8s %-12s (%-9s) %-12s" % (
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

# initialize BPF
b = BPF(text=bpf_text)

# header
print("%-22s -> %-22s %-10s %-10s %-8s %-8s %-12s (%-9s) %-12s" % \
    ("SADDR:SPORT", "DADDR:DPORT", "SEQ", "ACK", "RTT(us)", "CWnd", "STATE", "FLAGS", "DURATION"))

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
while 1:
    try:
        b.perf_buffer_poll()
        # b.trace_print()
    except KeyboardInterrupt:
        exit()
