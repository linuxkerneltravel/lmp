#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime

# for influxdb
from influxdb import InfluxDBClient
import lmp_influxdb as db
from db_modules import write2db

DBNAME = 'lmp'

client = db.connect(DBNAME,user='root',passwd=123456)

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 cpu;
    u32 pid;
    u32 tgid;
};

struct time_t {
    u64 total;
    u64 idle;
};

BPF_HASH(start, struct key_t);
BPF_HASH(dist, u32, struct time_t);

int pick_start(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct key_t key;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;

    start.update(&key, &ts);
    return 0;
}

int pick_end(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    struct key_t key;
    struct time_t cpu_time, *time_prev;
    u32 cpu;
    u32 pid;
    u64 *value;
    u64 delta;

    cpu = key.cpu = bpf_get_smp_processor_id();
    pid = key.pid = prev->pid;
    key.tgid = prev->tgid;

    value = start.lookup(&key);

    if (value == 0) {
        return 0;
    }

    delta = ts - *value;
    start.delete(&key);

    time_prev = dist.lookup(&cpu);

    if (time_prev == 0) {
        cpu_time.total = 0;
        cpu_time.idle = 0;
    }else {
        cpu_time = *time_prev;
    }

    cpu_time.total += delta;

    if (pid == 0) {
        cpu_time.idle += delta;
    }

    dist.update(&cpu, &cpu_time);

    return 0;
}
"""

# data structure from template
class lmp_data(object):
    def __init__(self,a,b,c,d,e):
            self.glob = a
            self.cpu = b
            self.total = c
            self.idle = d
            self.perce = e                   

data_struct = {"measurement":'picknext',
                "tags":['glob','cpu'],
                "fields":['total','idle','perce']}

b = BPF(text=bpf_text)
b.attach_kprobe(event="finish_task_switch", fn_name="pick_start")
b.attach_kprobe(event="finish_task_switch", fn_name="pick_end")

dist = b.get_table("dist")


while (1):
    try:
        sleep(1)
        print("%-6s%-16s%-16s%-6s" % ("CPU", "TOTAL(ns)", "IDLE(ns)", "PERCE"))
        for k, v in dist.items():
            print("%-6d%-16d%-16d%-6.4f%%" % (k.value, v.total, v.idle, 1.0 *(v.total - v.idle) / v.total * 100))
        dist.clear()
        print("--" * 20)
    except KeyboardInterrupt:
        exit()
    



