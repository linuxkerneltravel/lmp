#!/usr/bin/python3
from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
from time import sleep
from influxdb import InfluxDBClient
from datetime import datetime

client = InfluxDBClient('localhost', 8086, 'admin', '123456', 'lmp')  # ip,port,user,passwd,dbname

# arguments
examples = """examples:
    ./tcpconnect           # trace all TCP connect()s
    ./tcpconnect -t        # include timestamps
    ./tcpconnect -p 181    # only trace PID 181
    ./tcpconnect -P 80     # only trace port 80
    ./tcpconnect -P 80,81  # only trace port 80 and 81
    ./tcpconnect -U        # include UID
    ./tcpconnect -u 1000   # only trace UID 1000
    ./tcpconnect -c        # count connects per src ip and dest ip/port
    ./tcpconnect --cgroupmap mappath  # only trace cgroups in this BPF map
    ./tcpconnect --mntnsmap mappath   # only trace mount namespaces in the map
"""
# 创建参数解析对象，添加参数
parser = argparse.ArgumentParser(
    description="Trace TCP connects",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("-p", "--pid",
                    help="trace this PID only")
parser.add_argument("-P", "--port",
                    help="comma-separated list of destination ports to trace.")
parser.add_argument("-U", "--print-uid", action="store_true",
                    help="include UID on output")
parser.add_argument("-u", "--uid",
                    help="trace this UID only")
parser.add_argument("-c", "--count", action="store_true",
                    help="count connects per src ip and dest ip/port")
parser.add_argument("--cgroupmap",
                    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
                    help="trace mount namespaces in this BPF map only")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = BPF(src_file=r'./c/ContainerNet.c')
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID',
                                'if (pid != %s) { return 0; }' % args.pid)
if args.port:
    dports = [int(dport) for dport in args.port.split(',')]
    dports_if = ' && '.join(['dport != %d' % ntohs(dport) for dport in dports])
    bpf_text = bpf_text.replace('FILTER_PORT',
                                'if (%s) { currsock.delete(&pid); return 0; }' % dports_if)
if args.uid:
    bpf_text = bpf_text.replace('FILTER_UID',
                                'if (uid != %s) { return 0; }' % args.uid)
bpf_text = filter_by_containers(args) + bpf_text

bpf_text = bpf_text.replace('FILTER_PID', '')
bpf_text = bpf_text.replace('FILTER_PORT', '')
bpf_text = bpf_text.replace('FILTER_UID', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()


def subdata2db(conid, comm, ip, saddr, daddr, dport):
    current_time = datetime.now().isoformat()
    body = [
        {
            "measurement": "ContainerNet",
            "time": current_time,
            "tags": {
                "conid": conid
            },
            "fields": {
                "comm": comm,
                "ip": ip,
                "saddr": saddr,
                "daddr": daddr,
                "dport": dport
            },
        }
    ]
    client.write_points(body)


# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-8.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")
    # printb(b"%-6d %-12.12s %-12.12s %-2d %-16s %-16s %-4d" % (event.pid,event.container_id,
    #     event.task, event.ip,
    #     inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
    #     inet_ntop(AF_INET, pack("I", event.daddr)).encode(), event.dport))
    conid = event.container_id[0:7]
    comm = event.task
    ip = event.ip
    saddr = inet_ntop(AF_INET, pack("I", event.saddr)).encode()
    daddr = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    dport = event.dport
    subdata2db(conid, comm, ip, saddr, daddr, dport)


def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")
    printb(b"%-6d %-12.12s %-12.12s %-2d %-16s %-16s %-4d" % (event.pid, event.container_id,
                                                              event.task, event.ip,
                                                              inet_ntop(AF_INET6, event.saddr).encode(),
                                                              inet_ntop(AF_INET6, event.daddr).encode(),
                                                              event.dport))
    subdata2db(
        event.container_id,
        event.task,
        event.ip,
        inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
        inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
        event.dport
    )


# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

# print("Tracing connect ... Hit Ctrl-C to end")
# read events
# header
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")
if args.print_uid:
    print("%-6s" % ("UID"), end="")
print("%-6s %-12s %-12s %-2s %-16s %-16s %-4s" % ("PID", "CONTAINER_ID", "COMM", "IP", "SADDR",
                                                  "DADDR", "DPORT"))

start_ts = 0

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
