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
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/interrupt.h>

struct key_t {
    u32 cpu;
    u32 pid;
    u32 tgid;
};

BPF_HASH(enter, struct key_t);
BPF_HASH(exitt, struct key_t);

int handler_start(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct key_t key;
    
    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;
    key.cpu = bpf_get_smp_processor_id();

    enter.update(&key, &ts);
    return 0;
}

int handler_end(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *value;
    u64 delta;
    struct key_t key;

    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;
    key.cpu = bpf_get_smp_processor_id();

    value = enter.lookup(&key);

    if (value == 0) {
        return 0;
    }

    delta = ts - *value;
    enter. delete(&key);
    exitt.increment(key, delta);
    return 0;
}

"""

# data structure from template
class lmp_data(object):
    def __init__(self,a,b,c,d):
            self.glob = a
            self.cpu = b
            self.pid = c
            self.duration = d    

data_struct = {"measurement":'irq',
                "tags":['glob','cpu','pid'],
                "fields":['duration']}

b = BPF(text=bpf_text)
b.attach_kprobe(event="irq_enter", fn_name="handler_start")
b.attach_kprobe(event="irq_exit", fn_name="handler_end")

exitt = b.get_table("exitt")

print("%-6s%-6s%-6s%-6s" % ("CPU", "PID", "TGID", "TIME(us)"))
while (1):
    try:
        sleep(1)
        for k, v in exitt.items():
            print("%-6d%-6d%-6d%-6d" % (k.cpu, k.pid, k.tgid, v.value / 1000))
            test_data = lmp_data('glob', k.cpu, k.pid, v.value/1000)
            write2db(data_struct, test_data, client)
        exitt.clear()
    except KeyboardInterrupt:
        exit()

