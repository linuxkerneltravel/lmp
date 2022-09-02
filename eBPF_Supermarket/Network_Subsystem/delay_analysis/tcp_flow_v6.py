from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
from bcc import tcp
import argparse
# from tcptools import check_filename, valid_function_name

bpf_text = open('tcp_flow_v6.c').read()

# args parser
parser = argparse.ArgumentParser(description="Trace the TCP metrics with ACKs",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-sp", "--sport", help="trace this source port only")
parser.add_argument("-dp", "--dport", help="trace this destination port only")
parser.add_argument("-s", "--sample", help="Trace sampling")
parser.add_argument("-c", "--count", type=int, default=99999999, help="count of outputs")

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


# process event
def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    print("%-42s -> %-42s %-10s %-10s %-8s %-8s %-12s (%-9s) %-12s" % (
        "%s:%d" % (inet_ntop(AF_INET6, event.saddr), event.sport),
        "%s:%d" % (inet_ntop(AF_INET6, event.daddr), event.dport),
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
print("%-42s -> %-42s %-10s %-10s %-8s %-8s %-12s (%-9s) %-12s" % \
    ("SADDR:SPORT", "DADDR:DPORT", "SEQ", "ACK", "RTT(us)", "CWnd", "STATE", "FLAGS", "DURATION"))

# read events
b["ipv6_events"].open_perf_buffer(print_ipv6_event)

line = 0

while 1:
    try:
        b.perf_buffer_poll()
        # b.trace_print()
    except KeyboardInterrupt:
        exit()
    
    line += 1
    if line >= args.count:
        break
