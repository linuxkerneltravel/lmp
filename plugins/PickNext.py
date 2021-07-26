#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import sleep

# for influxdb
from settings.init_db import influx_client
from db_modules import write2db
from settings.const import DatabaseType

from datetime import datetime


# data structure from template
class lmp_data(object):
    def __init__(self, a, b, c, d, e):
        self.time = a
        self.glob = b
        self.cpu = c
        self.pid = d
        self.duration = e


data_struct = {"measurement": 'picknext',
               "time": [],
               "tags": ['glob', 'cpu', 'pid', ],
               "fields": ['duration']}

b = BPF(src_file=r'c/PickNext.c')
b.attach_kprobe(event="pick_next_task_fair", fn_name="pick_start")
b.attach_kretprobe(event="pick_next_task_fair", fn_name="pick_end")

dist = b.get_table("dist")

# print("%-6s%-6s%-6s%-6s" % ("CPU", "PID", "TGID", "TIME(ns)"))

while (1):
    try:
        sleep(1)
        for k, v in dist.items():
            # print("%-6d%-6d%-6d%-6d" % (k.cpu, k.pid, k.tgid, v.value))
            # test_data = lmp_data('glob', k.cpu, k.pid, v.value)
            test_data = lmp_data(datetime.now().isoformat(), 'glob', k.cpu, k.pid, v.value)
            write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
        dist.clear()
    except KeyboardInterrupt:
        exit()
