from __future__ import print_function
from bcc import DEBUG_BPF_REGISTER_STATE
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep, localtime, asctime, time
from collections import namedtuple, defaultdict

parser = argparse.ArgumentParser(description="Summarize TCP send/recv throughput by host",
    formatter_class=argparse.RawDescriptionHelpFormatter,)
parser.add_argument("-p", "--pid", help="trace this PID only")
parser.add_argument("-i", "--interval", type=float, default=1)
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true", help="trace IPv6 family only")
args = parser.parse_args()

print_interval = args.interval + 0.0
if print_interval <= 0:
    print ("print interval must stricly positive")
    exit()

bpf_text = open('tcp_bytes.c').read()

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('##FILTER_PID##',
        'if (pid != %s) { return 0; }' % args.pid)
    
if args.ipv4:
    bpf_text = bpf_text.replace('##FILTER_FAMILY##',
        'if (family != AF_INET) { return 0; }')
elif args.ipv6:
    bpf_text = bpf_text.replace('##FILTER_FAMILY##',
        'if (family != AF_INET6) { return 0; }')

bpf_text = bpf_text.replace('##FILTER_PID##', '')
bpf_text = bpf_text.replace('##FILTER_FAMILY##', '')


TCPSessionKey = namedtuple('TCPSession', ['pid', 'name', 'saddr', 'sport', 'daddr', 'dport'])

def get_ipv4_session_key(k):
    return TCPSessionKey(pid=k.pid,
                         name=k.task,
                         saddr=inet_ntop(AF_INET, pack("I", k.saddr)),
                         sport=k.sport,
                         daddr=inet_ntop(AF_INET, pack("I", k.daddr)),
                         dport=k.dport)

def get_ipv6_session_key(k):
    return TCPSessionKey(pid=k.pid,
                         name=k.task,
                         saddr=inet_ntop(AF_INET6, k.saddr),
                         sport=k.sport,
                         daddr=inet_ntop(AF_INET6, k.daddr),
                         dport=k.dport)

# initialize BPF
b = BPF(text=bpf_text)

ipv4_send = b["ipv4_send"]
ipv4_recv = b["ipv4_recv"]
ipv6_send = b["ipv6_send"]
ipv6_recv = b["ipv6_recv"]


while 1:
    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exit()

    # header
    print(asctime(localtime(time())))

    # IPv4: build dict of all seen keys
    ipv4_throughput = defaultdict(lambda: [0, 0])
    for k, v in ipv4_send.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][0] = v.value
    ipv4_send.clear()

    for k, v in ipv4_recv.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][1] = v.value
    ipv4_recv.clear()

    if ipv4_throughput:
        print("%-7s %-12s %-21s %-21s %6s %6s" % ("PID", "COMM",
            "SADDR", "DADDR", "RX_KB", "TX_KB"))

    # IPv4: output
    for k, (send_bytes, recv_bytes) in sorted(ipv4_throughput.items(),
                                              key=lambda kv: sum(kv[1]),
                                              reverse=True):
        print("%-7d %-12.12s %-21s %-21s %6d %6d" % (k.pid,
            k.name,
            k.saddr + ":" + str(k.sport),
            k.daddr + ":" + str(k.dport),
            int(recv_bytes / 1024), int(send_bytes / 1024)))

    # IPv6: build dict of all seen keys
    ipv6_throughput = defaultdict(lambda: [0, 0])
    for k, v in ipv6_send.items():
        key = get_ipv6_session_key(k)
        ipv6_throughput[key][0] = v.value
    ipv6_send.clear()

    for k, v in ipv6_recv.items():
        key = get_ipv6_session_key(k)
        ipv6_throughput[key][1] = v.value
    ipv6_recv.clear()

    if ipv6_throughput:
        # more than 80 chars, sadly.
        print("\n%-7s %-12s %-40s %-40s %6s %6s" % ("PID", "COMM",
            "SADDR6", "DADDR6", "RX_KB", "TX_KB"))

    # IPv6: output
    for k, (send_bytes, recv_bytes) in sorted(ipv6_throughput.items(),
                                              key=lambda kv: sum(kv[1]),
                                              reverse=True):
        print("%-7d %-12.12s %-40s %-40s %6d %6d" % (k.pid,
            k.name,
            k.saddr + ":" + str(k.sport),
            k.daddr + ":" + str(k.dport),
            int(recv_bytes / 1024), int(send_bytes / 1024)))
    
    print("-"*60)
