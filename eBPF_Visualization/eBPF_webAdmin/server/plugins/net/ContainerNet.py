#!/usr/bin/env python3
# -*- coding:utf-8 -*-
from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
from time import sleep

import sys
sys.path.append('./plugins/common/')
from influxdb import InfluxDBClient
from datetime import datetime


client = InfluxDBClient('localhost', 8086, 'admin', '123456', 'lmp')#ip,port,user,passwd,dbname

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
#创建参数解析对象，添加参数
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
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#define CONTAINER_ID_LEN 128
#include <linux/string.h>
//创建保存sockeet指针的哈希
BPF_HASH(currsock, u32, struct sock *);

// separate data structs for ipv4 and ipv6
//记录ipv4_tcp连接信息的结构体
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 dport;
    char task[TASK_COMM_LEN];
    char container_id[CONTAINER_ID_LEN];
};
//创建ipv4_tcp连接的输出
BPF_PERF_OUTPUT(ipv4_events);

//创建ipv6_tcp连接信息的结构体
struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 dport;
    char task[TASK_COMM_LEN];
    char container_id[CONTAINER_ID_LEN];
};
//创建ipv6_tcp连接的输出
BPF_PERF_OUTPUT(ipv6_events);

// separate flow keys per address family

//在进入tcp_v4_connect时调用
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    if (container_should_be_filtered()) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID

    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID

    currsock.update(&tid, &sk);//使用tid作为key,保存sk指针指向的地址

    return 0;
}
//在从tcp_v4_connect返回时调用
static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx);//获取tcp_v4_connect函数的返回值
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    

    struct sock **skpp;
    skpp = currsock.lookup(&tid);//判断当前线程在进入tcp_v4_connect时是否打点采集
    if (skpp == 0) {
        return 0;   // missed entry
    }

    if (ret != 0) {  //tcp_v4_connect返回值非0，没有发送syn报文
        currsock.delete(&tid); //采集失败，删除哈希
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 dport = skp->__sk_common.skc_dport;//获取到目的端口号

    FILTER_PORT
    char container_id[CONTAINER_ID_LEN]="0"; //容器id初始化
    struct task_struct *curr_task;
    struct css_set *css;
    struct cgroup_subsys_state *sbs;
    struct cgroup *cg;
    struct kernfs_node *knode, *pknode;
    curr_task = (struct task_struct *) bpf_get_current_task();
    css = curr_task->cgroups;
  bpf_probe_read(&sbs, sizeof(void *), &css->subsys[0]);
  bpf_probe_read(&cg,  sizeof(void *), &sbs->cgroup);
  bpf_probe_read(&knode, sizeof(void *), &cg->kn);
  bpf_probe_read(&pknode, sizeof(void *), &knode->parent);

  if(pknode != NULL) {
    char *aus;

    bpf_probe_read(&aus, sizeof(void *), &knode->name);
    bpf_probe_read_str(container_id, CONTAINER_ID_LEN, aus);
  }
    if (ipver == 4) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
               data4.uid = bpf_get_current_uid_gid();
               data4.ts_us = bpf_ktime_get_ns() / 1000;
               data4.saddr = skp->__sk_common.skc_rcv_saddr;
               data4.daddr = skp->__sk_common.skc_daddr;
               data4.dport = ntohs(dport);
               bpf_get_current_comm(&data4.task, sizeof(data4.task));
               bpf_probe_read_str(&data4.container_id,CONTAINER_ID_LEN,container_id);
               ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else /* 6 */ {
         struct ipv6_data_t data6 = {.pid = pid, .ip = ipver};
               data6.uid = bpf_get_current_uid_gid();
               data6.ts_us = bpf_ktime_get_ns() / 1000;
               bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
                   skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
               bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
                   skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
               data6.dport = ntohs(dport);
               bpf_get_current_comm(&data6.task, sizeof(data6.task));
               bpf_probe_read_str(&data6.container_id,CONTAINER_ID_LEN,container_id);
               ipv6_events.perf_submit(ctx, &data6, sizeof(data6));


    }

    currsock.delete(&tid);

    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}
"""
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

def subdata2db(conid,comm,ip,saddr,daddr,dport):
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
    conid=event.container_id[0:7]
    comm=event.task
    ip=event.ip
    saddr=inet_ntop(AF_INET, pack("I", event.saddr)).encode()
    daddr=inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    dport=event.dport
    subdata2db(conid,comm,ip,saddr,daddr,dport)


def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")
    printb(b"%-6d %-12.12s %-12.12s %-2d %-16s %-16s %-4d" % (event.pid,event.container_id,
        event.task, event.ip,
        inet_ntop(AF_INET6, event.saddr).encode(), inet_ntop(AF_INET6, event.daddr).encode(),
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

#print("Tracing connect ... Hit Ctrl-C to end")
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
