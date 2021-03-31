#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime

# for influxdb
from const import DatabaseType
from init_db import influx_client
from db_modules import write2db

from datetime import datetime


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

int pick_start(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct key_t key;
    struct time_t cpu_time, *time_prev;
    u32 cpu, pid;
    u64 *value, delta;

    cpu = key.cpu = bpf_get_smp_processor_id();
    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;

    start.update(&key, &ts);

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
    def __init__(self, a, b, c):
        self.time = a
        self.glob = b
        self.perce = c


data_struct = {"measurement": 'cpuutilize',
               "time": [],
               "tags": ['glob', ],
               "fields": ['perce']}

b = BPF(text=bpf_text)
b.attach_kprobe(event="finish_task_switch", fn_name="pick_start")

dist = b.get_table("dist")

cpu = [0, 0]
# times = 0

while (1):
    try:
        sleep(1)
        for k, v in dist.items():
            cpu[k.value] = 1.0 * (v.total - v.idle) / v.total * 100
            #times += 1
            #print("%-6d%-16d%-16d%-6.4f%%" % (k.value, v.total, v.idle, 1.0 *(v.total - v.idle) / v.total * 100))
            test_data = lmp_data(
                datetime.now().isoformat(), 'glob', cpu[k.value])
            write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
        dist.clear()

    except KeyboardInterrupt:
        exit()
