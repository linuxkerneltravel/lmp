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
    description = "Summarize send and recv flow by host",
    formatter_class = argparse.RawDescriptionHelpFormatter,
    epilog = examples
)
parser.add_argument("interval", nargs="?", default=1, type=range_check,
	help = "output interval, in second (default 1)")
parser.add_argument("count", nargs="?", default=-1, type=range_check,
	help="number of outputs")
args = parser.parse_args()

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/string.h>
#define CONTAINER_ID_LEN 128

struct ipv4_key_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
    char container_id[CONTAINER_ID_LEN];
};
BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);
BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{       char container_id[CONTAINER_ID_LEN]="0"; //容器id初始化
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
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u16 dport = 0, family = sk->__sk_common.skc_family;
    
    if (family == AF_INET) {
        //bpf_probe_read(&ipv4_key.saddr, sizeof(ipv4_key.saddr), &sk->__sk_common.skc_rcv_saddr);
        struct ipv4_key_t ipv4_key = {.pid = pid};
        bpf_get_current_comm(&ipv4_key.task, sizeof(ipv4_key.task));
        bpf_probe_read_str(&ipv4_key.container_id,CONTAINER_ID_LEN,container_id);
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        ipv4_send_bytes.increment(ipv4_key, size);
        
    }
    return 0;
}
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
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
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u16 dport = 0, family = sk->__sk_common.skc_family;
    u64 *val, zero =0;

    if (copied <= 0)
        return 0;

    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        bpf_get_current_comm(&ipv4_key.task, sizeof(ipv4_key.task));
        bpf_probe_read_str(&ipv4_key.container_id,CONTAINER_ID_LEN,container_id);
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        ipv4_recv_bytes.increment(ipv4_key, copied);
    }
    return 0;
}
"""

#database
def subdata2db(conid,comm,rx,tx,tcpsum):
    current_time = datetime.now().isoformat()
    body = [
        {
            "measurement": "tcpflow",
            "time": current_time,
            "tags": {
                "conid": conid
            },
            "fields": {
                "comm": comm,
                "rx":rx,
                "tx":tx,
                "tcpsum":tcpsum,
            },
        }
    ]
    client.write_points(body)


SessionKey = namedtuple('Session',['pid','container_id', 'task','laddr', 'lport', 'daddr', 'dport'])

def get_pod_name(arg):
    cmd="bash 1.sh %s" %(arg)
    str=os.popen(cmd).read()
    return str

def get_ipv4_session_key(k):
	return SessionKey(pid=k.pid, container_id=str(k.container_id,encoding="UTF-8"),task=str(k.task,encoding="UTF-8"),laddr=inet_ntop(AF_INET, pack("I", k.saddr)), 
		lport=k.lport, daddr=inet_ntop(AF_INET, pack("I", k.daddr)), dport=k.dport)


# init bpf
b = BPF(text=bpf_program)

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

	ipv4_throughput = defaultdict(lambda:[0,0])
	for k, v in ipv4_send_bytes.items():
		key=get_ipv4_session_key(k)
		ipv4_throughput[key][0] = v.value
	ipv4_send_bytes.clear()

	for k,v in ipv4_recv_bytes.items():
		key = get_ipv4_session_key(k)
		ipv4_throughput[key][1] = v.value
	ipv4_recv_bytes.clear()
	#lock.acquire()
	if ipv4_throughput:
		for k, (send_bytes, recv_bytes) in sorted(ipv4_throughput.items(),
			key=lambda kv: sum(kv[1]),
			reverse=True):
			recv_bytes = int(recv_bytes / 1024)
			send_bytes = int(send_bytes / 1024)
			sumrecv += recv_bytes
			sumsend += send_bytes
			sum_kb = sumrecv + sumsend
			c_id=k.container_id
			container_id=c_id[:12]
		if(container_id!='0'):
                    conid=k.container_id[0:7]
                    comm=k.task
                    rx=sumrecv
                    tx=sumsend
                    tcpsum=sum_kb
                    subdata2db(conid,comm,rx,tx,tcpsum)

                        
	#lock.release()

	i += 1

