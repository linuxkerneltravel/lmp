#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import sleep

# for influxdb
from settings.init_db import influx_client
from db_modules import write2db
from settings.const import DatabaseType

from datetime import datetime

bpf_text = BPF(src_file=r'c/Irq.c')


# data structure from template
class lmp_data(object):
    def __init__(self, a, b, c, d, e):
        self.time = a
        self.glob = b
        self.cpu = c
        self.pid = d
        self.duration = e


data_struct = {"measurement": 'irq',
               "time": [],
               "tags": ['glob', 'cpu', 'pid'],
               "fields": ['duration']}

b = BPF(text=bpf_text)
b.attach_kprobe(event="irq_enter", fn_name="handler_start")
b.attach_kprobe(event="irq_exit", fn_name="handler_end")

exitt = b.get_table("exitt")

# print("%-6s%-6s%-6s%-6s" % ("CPU", "PID", "TGID", "TIME(us)"))
while (1):
    try:
        sleep(1)
        for k, v in exitt.items():
            # print("%-6d%-6d%-6d%-6d" % (k.cpu, k.pid, k.tgid, v.value / 1000))
            test_data = lmp_data(datetime.now().isoformat(), 'glob', k.cpu, k.pid, v.value / 1000)
            write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
        exitt.clear()
    except KeyboardInterrupt:
        exit()
