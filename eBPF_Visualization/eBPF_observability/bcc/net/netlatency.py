#!/usr/bin/env python3
# -*- coding:utf-8 -*-
from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import argparse

# for influxdb
import sys
sys.path.append('./plugins/common/')
from init_db import influx_client
from db_modules import write2db
from const import DatabaseType

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
bpf_text = """
#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <bcc/proto.h>
struct ipv4_data_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u8 ip;
    u16 dport;
    u16 sport;
    char task[TASK_COMM_LEN];
    u32 srtt;
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u8 ip;
    u16 dport;
    u16 sport;
    char task[TASK_COMM_LEN];
    u32 srtt;
};
BPF_PERF_OUTPUT(ipv6_events);

BPF_HASH(tmp, u64, struct sock *);

int trace_tcp_ack_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid = bpf_get_current_pid_tgid();
    tmp.update(&pid, &sk);
    return 0;
}

int trace_tcp_ack_return(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	if (ret != 1)
	    return 0;

        u64 pid = bpf_get_current_pid_tgid();
        struct sock **skp;
        skp = tmp.lookup(&pid);
        if (skp == 0)
            return 0;
        tmp.delete(&pid);

        struct sock *sk = *skp;
	if (sk->__sk_common.skc_state != TCP_ESTABLISHED)
            return 0;
	
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	u32 srtt = (tp->srtt_us >> 3);
	FILTER {
		u32 pid_t = pid >> 32;
		u16 dport = sk->__sk_common.skc_dport;
		u16 sport = sk->__sk_common.skc_num;
		u16 family = sk->__sk_common.skc_family;
		if (family == AF_INET) {
			struct ipv4_data_t data4 = {.pid = pid_t, .ip = 4, .srtt = srtt};
			bpf_get_current_comm(&data4.task, sizeof(data4.task));
			data4.saddr = sk->__sk_common.skc_rcv_saddr;
			data4.daddr = sk->__sk_common.skc_daddr;
			data4.sport = sport;
			data4.dport = ntohs(dport);
			ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
		} else {
			struct ipv6_data_t data6 = {.pid = pid_t, .ip = 6, .srtt = srtt};
			bpf_get_current_comm(&data6.task, sizeof(data6.task));
			bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
								  sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
			bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
								  sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
			data6.sport = sport;
			data6.dport = ntohs(dport);
			ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
		}	
	}

	return 0;
}
"""

# data structure from template
class lmp_data(object):
    def __init__(self,a,b,c,d,e):
            self.glob = a
            self.ip = b
            self.comm = c
            self.pid = d
            self.srtt = e

data_struct = {"measurement":'netlatency',
                "tags":['glob','ip','comm','pid'],
                "fields":['srtt']}


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
        #test_data = lmp_data('glob', 'ipv4', event.task.decode('utf-8', 'replace'), event.pid, event.srtt)
        #write2db(data_struct, test_data, client)
    
    # test_data = lmp_data('glob', 'ipv4',event.task.decode('utf-8', 'replace'), event.pid, event.srtt)
    # write2db(data_struct, test_data, client)
    #print('glob', event.srtt)
    #test_data = lmp_data('glob', event.srtt)
    #write2db(data_struct, test_data, client)

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    if event.task.decode('utf-8', 'replace') != 'influxd' and event.task.decode('utf-8', 'replace') != 'docker-proxy':
        test_data = lmp_data('glob', 'ipv6', event.task.decode('utf-8', 'replace'), event.pid, event.srtt)
        write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
        print("%-6d %-12.12s %-2d %-20s > %-20s %d" % (
        event.pid, event.task.decode('utf-8', 'replace'), event.ip,
        "%s:%d" % (inet_ntop(AF_INET6, event.saddr), event.sport),
        "%s:%d" % (inet_ntop(AF_INET6, event.daddr), event.dport), event.srtt))
    #print(test_data)
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
