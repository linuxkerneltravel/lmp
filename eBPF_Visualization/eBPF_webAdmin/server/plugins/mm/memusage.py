#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from bcc import BPF
import os
from time import sleep
import _thread

# for influxdb
import sys
sys.path.append('./plugins/common/')
from init_db import influx_client
from db_modules import write2db

from datetime import datetime
from const import DatabaseType


title = ['DMA', 'DMA32', 'Normal']
#print("%-9s%-9s%-9s" % (title[0], title[1], title[2]))

# data structure from template


class lmp_data(object):
    def __init__(self, a, b, c, d, e):
        self.time = a
        self.glob = b
        self.dma = c
        self.dma32 = d
        self.normal = e


data_struct = {"measurement": 'memusage',
               "time": [],
               "tags": ['glob'],
               "fields": ['dma', 'dma32', 'normal']}


def load_BPF(thread_name, delay):
    b = BPF(text='''
            #include <uapi/linux/ptrace.h>

            int kprobe_wakeup_kswapd(struct pt_regs *ctx)
            {
                    bpf_trace_printk("Tracing for function of wakeup_kswapd...\\n");
                    bpf_trace_printk("WARNING:A zone is low on free memory!\\n");

                    return 0;
            }
            ''')

    b.trace_print()


def zone_info(thread_name, delay):
    path = "/proc/zoneinfo"
    title = ['DMA', 'DMA32', 'Normal']
    data = ['0', '0', '0']
    while 1:
        try:
            sleep(1)
        except KeyboardInterrupt:
            exit()
        f = open(path)
        line = f.readline()
        pages_free = '0'
        managed = '0'
        count = 0
        i = 0
        k = 0
        # print(title)
        while line:
            if ':' in line:
                line = line.replace(':', '')
            strline = line.split()
            # if strline[3] == 'DMA':
            if strline[0] == 'pages':
                pages_free = strline[2]
                count = count + 1
            if strline[0] == 'managed':
                managed = strline[1]
                count = count + 1
            if pages_free != '0' and managed != '0' and count == 2:
                result = float(pages_free)/float(managed)
                if i == 0:
                    data[i] = "%.4f" % result
                elif i == 1:
                    data[i] = "%.4f" % result
                elif i == 2:
                    data[i] = "%.4f" % result
                i = i+1
                count = 0

            line = f.readline()
        # print(data)
        print("%-9s%-9s%-9s" % (data[0], data[1], data[2]))
        test_data = lmp_data(datetime.now().isoformat(),
                             'glob', data[0], data[1], data[2])
        write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
        # print('------------')
        f.close()


try:
    _thread.start_new_thread(load_BPF, ("BPF progream", 0))
    _thread.start_new_thread(zone_info, ("zoneinfo", 10))
except:
    print("Error:unable to start thread")

while 1:
    try:
        pass
    except KeyboardInterrupt:
        exit()
