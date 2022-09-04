from __future__ import print_function
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
parser.add_argument("-r", "--direction", help="trace this direction only") # 'accept' or 'connect'
parser.add_argument("-c", "--count", type=int, default=99999999, help="count of outputs")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true", help="trace IPv6 family only")
args = parser.parse_args()

bpf_text = open('tcp_connection.c').read()

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

# b.trace_print()

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)

line = 0

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
    
    line += 1
    if line >= args.count:
        break
