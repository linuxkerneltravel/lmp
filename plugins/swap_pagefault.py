#!/usr/bin/env python
# coding=utf-8

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime

# for influxdb
from influxdb import InfluxDBClient
import lmp_influxdb as db
from db_modules import write2db

from datetime import datetime


DBNAME = 'lmp'

client = db.connect(DBNAME,user='root',passwd=123456)

b = BPF(text = '''
        #include <uapi/linux/ptrace.h>
        #include <linux/ktime.h>
        
        BPF_HASH(timer, u32, ktime_t);
      
        int kprobe__do_swap_page(struct pt_regs *ctx)
        {
               
                u32 pid = bpf_get_current_pid_tgid();
             
                ktime_t start = bpf_ktime_get_ns();
                timer.update(&pid, &start);

                return 0;
        }
   
        int kretprobe__do_swap_page(struct pt_regs *ctx)
        {
             
                ktime_t end = bpf_ktime_get_ns();
                int ret = PT_REGS_RC(ctx);
                
                u32 pid = bpf_get_current_pid_tgid();
                
                ktime_t delta;
                
                ktime_t *tsp = timer.lookup(&pid);
                if ((ret >= 0) && (tsp != NULL))
                        delta = end - *tsp;
         
                if (delta >= 10000000) {/* 大于10ms的进行输出 */
                        bpf_trace_printk("%lld\\n", delta);
                }

                //bpf_trace_printk("%lld\\n", delta);

                return 0;
        }
        ''')


# data structure from template
class lmp_data(object):
    def __init__(self,a,b,c):
            self.time = a
            self.glob = b
            self.duration = c

data_struct = {"measurement":'swap_pagefault',
               "time":[],
               "tags":['glob'],
               "fields":['duration']}



timer = b.get_table("timer")

#print("%-6s%-6s%-6s%-6s" % ("CPU", "PID", "TGID", "TIME(us)"))
while (1):
    try:
        sleep(1)
        for k, v in timer.items():
            #print("%-6d%-6d%-6d%-6d" % (k.cpu, k.pid, k.tgid, v.value / 1000))
            test_data = lmp_data(datetime.now().isoformat(),'glob', v.value/1000)
            write2db(data_struct, test_data, client)
            #print("This is success")
        timer.clear()
    except KeyboardInterrupt:
        exit()




