# tcp_rcv_established()->tcp_validate_incoming()：如果有SYN且seq >= rcv_nxt，加１
# 以下函数内，如果checksum错误或者包长度小于TCP header，加１：
# tcp_v4_do_rcv()
# tcp_v4_rcv()
# tcp_v6_do_rcv()
# tcp_v6_rcv()

from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import argparse
from time import strftime
from bcc import tcp

REASONS = {
    0: "invalid seq",
    1: "invalid doff",
    2: "checksum",
}

# arguments
parser = argparse.ArgumentParser(description="Trace TCP connections",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", help="trace this PID only")
parser.add_argument("-c", "--count", type=int, default=99999999, help="count of outputs")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
                   help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
                   help="trace IPv6 family only")
args = parser.parse_args()

bpf_text = open('tcp_inerrs.c').read()

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('##FILTER_PID##',
                                'if (pid != %s) { return 0; }' % args.pid)

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

bpf_text = bpf_text.replace('##FILTER_PID##', '')
bpf_text = bpf_text.replace('##FILTER_FAMILY##', '')
bpf_text = bpf_text.replace('##FILTER_FAMILY4##', '')
bpf_text = bpf_text.replace('##FILTER_FAMILY6##', '')


def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    print("%-9s %-7s %-12s %-2s %-24s > %-24s %-12s %s" % (
        strftime("%H:%M:%S"),
        event.pid, str(event.task, 'utf-8'), event.ip,
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.sport),
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
        REASONS[event.reason],
        tcp.tcpstate[event.state]))


def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    print("%-9s %-7s %-12s %-2s %-24s > %-24s %-12s %s" % (
        strftime("%H:%M:%S"),
        event.pid, str(event.task, 'utf-8'), event.ip,
        "%s:%d" % (inet_ntop(AF_INET6, event.saddr), event.sport),
        "%s:%d" % (inet_ntop(AF_INET6, event.daddr), event.dport),
        REASONS[event.reason],
        tcp.tcpstate[event.state]))


b = BPF(text=bpf_text, debug=0x8)



# header
print("%-9s %-7s %-12s %-2s %-24s > %-24s %-12s %s" % ("TIME", "PID", "COMM", "IP",
                                                            "SADDR:SPORT", "DADDR:DPORT", "REASON", "STATE"))

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