#!/usr/bin/env python
# coding=utf-8
from __future__ import print_function
from bcc import BPF
from time import sleep
import argparse
from collections import namedtuple, defaultdict
from threading import Thread, currentThread, Lock
from socket import inet_ntop, AF_INET
from struct import pack
from time import sleep, strftime
from subprocess import call
import os

from influxdb import InfluxDBClient
from datetime import datetime

client = InfluxDBClient('localhost', 8086, 'admin', '123456', 'lmp')

examples = """examples:
    ./flow          # trace send/recv flow by host 
"""


def range_check(string):
    value = int(string)
    if value < 1:
        msg = "value must be stricly positive, got %d" % (value,)
        raise argparse.ArgumentTypeError(msg)
    return value


parser = argparse.ArgumentParser(
    description="Summarize send and recv flow by host",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples
)
parser.add_argument("interval", nargs="?", default=1, type=range_check,
                    help="output interval, in second (default 1)")
parser.add_argument("count", nargs="?", default=-1, type=range_check,
                    help="number of outputs")
args = parser.parse_args()


def subdata2db(conid, comm, rx, tx, udpsum):
    current_time = datetime.now().isoformat()
    body = [
        {
            "measurement": "udpflow",
            "time": current_time,
            "tags": {
                "conid": conid
            },
            "fields": {
                "comm": comm,
                "rx": rx,
                "tx": tx,
                "udpsum": udpsum,
            },
        }
    ]
    client.write_points(body)


SessionKey = namedtuple('Session', ['pid', 'container_id', 'task', 'laddr', 'lport', 'daddr', 'dport'])


def get_pod_name(arg):
    # cmd="bash 1.sh %s" %(arg)
    # str=os.popen(cmd).read()
    str = "null"
    return str


def get_ipv4_session_key(k):
    return SessionKey(pid=k.pid, container_id=str(k.container_id, encoding="UTF-8"), task=str(k.task, encoding="UTF-8"),
                      laddr=inet_ntop(AF_INET, pack("I", k.saddr)),
                      lport=k.lport, daddr=inet_ntop(AF_INET, pack("I", k.daddr)), dport=k.dport)


# init bpf
b = BPF(src_file=r'./c/UdpFlow.c')

ipv4_send_bytes = b["ipv4_send_bytes"]
ipv4_recv_bytes = b["ipv4_recv_bytes"]

# header
'''print("%-10s %-12s %-14s %-12s %-10s %-10s %-10s %-21s %-21s" % ("PID","CONTAINER_ID","PODNAME","COMM", 
	 "RXSUM_KB", "TXSUM_KB", "SUM_KB", "LADDR:LPORT", "DADDR:DPORT"))
'''

# output
sumrecv = 0
sumsend = 0
sum_kb = 0
i = 0
exiting = False
while i != args.count and not exiting:
    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exiting = True

    ipv4_throughput = defaultdict(lambda: [0, 0])
    for k, v in ipv4_send_bytes.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][0] = v.value
    ipv4_send_bytes.clear()

    for k, v in ipv4_recv_bytes.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][1] = v.value
    ipv4_recv_bytes.clear()
    # lock.acquire()
    if ipv4_throughput:
        for k, (send_bytes, recv_bytes) in sorted(ipv4_throughput.items(),
                                                  key=lambda kv: sum(kv[1]),
                                                  reverse=True):
            recv_bytes = int(recv_bytes / 1024)
            send_bytes = int(send_bytes / 1024)
            sumrecv += recv_bytes
            sumsend += send_bytes
            sum_kb = sumrecv + sumsend
            c_id = k.container_id
            container_id = c_id[:12]
        if (container_id != '0'):
            conid = k.container_id
            comm = k.task
            rx = sumrecv
            tx = sumsend
            udpsum = sum_kb
            subdata2db(conid, comm, rx, tx, udpsum)
            podname = get_pod_name(container_id)
    # print("%-10d %-12.12s %-14.14s  %-12.12s %-10d %-10d %-10d %-21s %-21s" %
    #	(k.pid, k.container_id,podname,k.task,
    #	 sumrecv, sumsend, sum_kb,
    #	k.laddr + ":" + str(k.lport),
    #	k.daddr + ":" + str(k.dport),))
    # lock.release()

    i += 1
