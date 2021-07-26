#!/usr/bin/python
from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import argparse

# for influxdb
import utils
from settings.const import DatabaseType
from settings.init_db import influx_client
from db_modules import write2db

examples = """examples:
    ./srtt           # default 1000us
    ./srtt -r 2000    # define xx_us
"""

parser = argparse.ArgumentParser(
    description="Network delay monitoring",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-r", "--rtt",
                    help="Define own delay time")
args = parser.parse_args()

# define BPF program
bpf_text = utils.read_c_program(r'c/NetworkLatency.c')


# data structure from template
class lmp_data(object):
    def __init__(self, a, b, c, d, e):
        self.glob = a
        self.ip = b
        self.comm = c
        self.pid = d
        self.srtt = e


data_struct = {"measurement": 'netlatency',
               "tags": ['glob', 'ip', 'comm', 'pid'],
               "fields": ['srtt']}

# code substitutions
if args.rtt:
    bpf_text = bpf_text.replace('FILTER',
                                'if (srtt >= %s)' % args.rtt)
else:
    bpf_text = bpf_text.replace('FILTER', 'if (srtt >= 1)')

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_ack", fn_name="trace_tcp_ack_entry")
b.attach_kretprobe(event="tcp_ack", fn_name="trace_tcp_ack_return")


# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    if event.task.decode('utf-8', 'replace') != 'influxd' and event.task.decode('utf-8', 'replace') != 'docker-proxy':
        print("%-6d %-12.12s %-2d %-20s > %-20s %d" % (
            event.pid, event.task.decode('utf-8', 'replace'), event.ip,
            "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.sport),
            "%s:%d" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport), event.srtt))
        # test_data = lmp_data('glob', 'ipv4', event.task.decode('utf-8', 'replace'), event.pid, event.srtt)
        # write2db(data_struct, test_data, client)

    # test_data = lmp_data('glob', 'ipv4',event.task.decode('utf-8', 'replace'), event.pid, event.srtt)
    # write2db(data_struct, test_data, client)
    # print('glob', event.srtt)
    # test_data = lmp_data('glob', event.srtt)
    # write2db(data_struct, test_data, client)


def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    if event.task.decode('utf-8', 'replace') != 'influxd' and event.task.decode('utf-8', 'replace') != 'docker-proxy':
        test_data = lmp_data('glob', 'ipv6', event.task.decode('utf-8', 'replace'), event.pid, event.srtt)
        write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
        print("%-6d %-12.12s %-2d %-20s > %-20s %d" % (
            event.pid, event.task.decode('utf-8', 'replace'), event.ip,
            "%s:%d" % (inet_ntop(AF_INET6, event.saddr), event.sport),
            "%s:%d" % (inet_ntop(AF_INET6, event.daddr), event.dport), event.srtt))
    # print(test_data)
    # test_data = lmp_data('glob', 'ipv6', event.task.decode('utf-8', 'replace'), event.pid, event.srtt)
    # write2db(data_struct, test_data, client)


# header
print("%-6s %-12s %-2s %-20s %-20s %s" % ("PID", "COMM", "IP", "SADDR:SPORT",
                                          "DADDR:DPORT", "srtt(us)"))

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
