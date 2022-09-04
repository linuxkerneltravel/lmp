from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import argparse


bpf_text = open('delay_analysis_in.c').read()

#------------
# args parser
parser = argparse.ArgumentParser(description="Trace time delay in network subsystem",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-sp", "--sport", help="trace this source port only")
parser.add_argument("-dp", "--dport", help="trace this destination port only")
parser.add_argument("-s", "--sample", help="Trace sampling")
parser.add_argument("-c", "--count", type=int, default=99999999, help="count of outputs")

args = parser.parse_args()

# code substitutions
if args.sport:
    bpf_text = bpf_text.replace('##FILTER_SPORT##', 'if (pkt_tuple.sport != %s) { return 0; }' % args.sport)
    
if args.dport:
    bpf_text = bpf_text.replace('##FILTER_DPORT##', 'if (pkt_tuple.dport != %s) { return 0; }' % args.dport)
    
if args.sample:
    bpf_text = bpf_text.replace('##SAMPLING##', 'if (((pkt_tuple.seq + pkt_tuple.ack + skb->len) << (32-%s) >> (32-%s)) != ((0x01 << %s) - 1)) { return 0;}' % (args.sample, args.sample, args.sample))
    

bpf_text = bpf_text.replace('##FILTER_SPORT##', '')
bpf_text = bpf_text.replace('##FILTER_DPORT##', '')
bpf_text = bpf_text.replace('##SAMPLING##', '')


# process event
def print_event(cpu, data, size):
    event = b["timestamp_events"].event(data)
    print("%-22s -> %-22s %-12s %-12s %-20s %-10s %-10s %-10s %-10s" % (
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.sport),
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
        "%d" % (event.seq),
        "%d" % (event.ack),
        "%f" % (event.mac_timestamp*1e-9),
        "%d" % (event.total_time/1000),
        "%d" % (event.mac_time/1000),
        "%d" % (event.ip_time/1000),
        "%d" % (event.tcp_time/1000)
    ))


# initialize BPF
b = BPF(text=bpf_text)

# header
print("%-22s -> %-22s %-12s %-12s %-20s %-10s %-10s %-10s %-10s" % \
    ("SADDR:SPORT", "DADDR:DPORT", "SEQ", "ACK", "TIME", "TOTAL", "MAC", "IP", "TCP"))

# read events
b["timestamp_events"].open_perf_buffer(print_event)

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