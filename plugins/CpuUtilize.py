#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from time import sleep

# for influxdb
from settings.const import DatabaseType
from settings.init_db import influx_client
from db_modules import write2db

from datetime import datetime


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

b = BPF(src_file=r'./c/CpuUtilize.c')
b.attach_kprobe(event="finish_task_switch", fn_name="pick_start")

dist = b.get_table("dist")

cpu = [0, 0]
# times = 0

while (True):
    try:
        sleep(1)
        for k, v in dist.items():
            cpu[k.value] = 1.0 * (v.total - v.idle) / v.total * 100
            # times += 1
            # print("%-6d%-16d%-16d%-6.4f%%" % (k.value, v.total, v.idle, 1.0 *(v.total - v.idle) / v.total * 100))
            test_data = lmp_data(
                datetime.now().isoformat(), 'glob', cpu[k.value])
            write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
        dist.clear()

    except KeyboardInterrupt:
        exit()
