#!/usr/bin/python
from __future__ import print_function
from bcc import BPF
import re, signal, sys
from time import sleep

# for influxdb
from settings.init_db import influx_client
from db_modules import write2db

from datetime import datetime

# load BPF program
b = BPF(src_file=r'./c/DiskReadWriteTime.c', debug=0)


# data structure from template
class lmp_data(object):
    def __init__(self, a, b, c, d, e, f, g, h):
        self.time = a
        self.glob = b
        self.comm = c
        self.pid = d
        self.disk = e
        self.t = f
        self.bytes = g
        self.lat = h


data_struct = {"measurement": 'HardDiskReadWriteTime',
               "time": [],
               "tags": ['glob', 'comm', 'pid', ],
               "fields": ['disk', 't', 'bytes', 'lat']}

if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="trace_pid_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_pid_start")
b.attach_kprobe(event="blk_account_io_completion",
                fn_name="trace_req_completion")

TASK_COMM_LEN = 16  # linux/sched.h
DISK_NAME_LEN = 32  # linux/genhd.h
# header
# print("%-14s %-14s %-6s %-7s %-2s %-22s %-10s %7s " % ("TIME(s)", "COMM", "PID",
#     "DISK", "T", "SECTOR", "BYTES", "LAT(ms)"))

rwflg = ""
start_ts = 0
prev_ts = 0
delta = 0


# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    val = -1
    global start_ts
    global prev_ts
    global delta
    if event.rwflag == 1:
        rwflg = "W"
    if event.rwflag == 0:
        rwflg = "R"
    if not re.match(b'\?', event.name):
        val = event.sector
    if start_ts == 0:
        prev_ts = start_ts
    if start_ts == 1:
        delta = float(delta) + (event.ts - prev_ts)
    # print("%-14.9f %-14.14s %-6s %-7s %-2s %-22s %-7s %7.2f " % (
    #     delta / 1000000, event.name.decode('utf-8', 'replace'), event.pid,
    #     event.disk_name.decode('utf-8', 'replace'), rwflg, val,
    #     event.len, float(event.delta) / 1000000))
    test_data = lmp_data(datetime.now().isoformat(), 'glob', event.name.decode('utf-8', 'replace'), event.pid,
                         event.disk_name.decode('utf-8', 'replace'), rwflg,
                         event.len, float(event.delta) / 1000000)
    # print(event.pid, time)
    write2db(data_struct, test_data, influx_client, 1)
    prev_ts = event.ts
    start_ts = 1


def quit(signum, frame):
    sys.exit()


# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        sleep(1)
        signal.signal(signal.SIGINT, quit)
        signal.signal(signal.SIGTERM, quit)
        b.perf_buffer_poll()
        print()
    except Exception as exc:
        print(exc)
    # except KeyboardInterrupt:
    #     db.close()
    #     exit()
