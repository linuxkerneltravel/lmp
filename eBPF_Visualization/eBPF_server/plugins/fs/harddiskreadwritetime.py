#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from __future__ import print_function
from bcc import BPF
import re, signal, sys
from time import sleep

# for influxdb
import sys
sys.path.append('./plugins/common/')
from init_db import influx_client
from db_modules import write2db

from datetime import datetime

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
struct val_t {
    u32 pid;
    char name[TASK_COMM_LEN];
    u64 ts;
};
struct data_t {
    u32 pid;
    u64 rwflag;
    u64 delta;
    u64 sector;
    u64 len;
    u64 ts;
    char disk_name[DISK_NAME_LEN];
    char name[TASK_COMM_LEN];
};
BPF_HASH(infobyreq, struct request *, struct val_t);
BPF_PERF_OUTPUT(events);
// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct val_t val = {};
    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.pid = bpf_get_current_pid_tgid();
        val.ts = bpf_ktime_get_ns();
        infobyreq.update(&req, &val);
    }
    return 0;
}
// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u64 delta;
    u32 *pidp = 0;
    struct val_t *valp;
    struct data_t data = {};
    u64 ts;
    // fetch timestamp and calculate delta
    ts = bpf_ktime_get_ns();
    //if(data.delta < 1000000){
    //   return 0;    
    //}
    valp = infobyreq.lookup(&req);
    //data.delta = ts - valp->ts;
    data.ts = ts/1000;
    if (valp == 0) {
        data.len = req->__data_len;
        strcpy(data.name, "?");
    } else {
        data.delta = ts - valp->ts;
        data.pid = valp->pid;
        data.len = req->__data_len;
        data.sector = req->__sector;
        bpf_probe_read(&data.name, sizeof(data.name), valp->name);
        struct gendisk *rq_disk = req->rq_disk;
        bpf_probe_read(&data.disk_name, sizeof(data.disk_name),
                       rq_disk->disk_name);
    }
#ifdef REQ_WRITE
    data.rwflag = !!(req->cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    data.rwflag = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    data.rwflag = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif
    events.perf_submit(ctx, &data, sizeof(data));
    infobyreq.delete(&req);
    return 0;
}
""", debug=0)

# data structure from template
class lmp_data(object):
    def __init__(self,a,b,c,d,e,f,g,h):
            self.time = a
            self.glob = b
            self.comm = c
            self.pid = d
            self.disk = e
            self.t = f
            self.bytes = g
            self.lat = h
                    

data_struct = {"measurement":'HardDiskReadWriteTime',
               "time":[],
               "tags":['glob','comm','pid',],
               "fields":['disk','t','bytes','lat']}

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
    test_data = lmp_data(datetime.now().isoformat(),'glob', event.name.decode('utf-8', 'replace'), event.pid,
        event.disk_name.decode('utf-8', 'replace'), rwflg,
        event.len, float(event.delta) / 1000000)
    # print(event.pid, time)
    write2db(data_struct, test_data, influx_client,1)
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
