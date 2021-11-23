#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from __future__ import print_function
from bcc import BPF

# load BPF program
# struct sysinfo {
	# __kernel_long_t uptime;		/* Seconds since boot */
	# __kernel_ulong_t loads[3];	/* 1, 5, and 15 minute load averages */
	# __kernel_ulong_t totalram;	/* Total usable main memory size */
	# __kernel_ulong_t freeram;	    /* Available memory size */
	# __kernel_ulong_t sharedram;	/* Amount of shared memory */
	# __kernel_ulong_t bufferram;	/* Memory used by buffers */
	# __kernel_ulong_t totalswap;	/* Total swap space size */
	# __kernel_ulong_t freeswap;	/* swap space still available */
	# __u16 procs;		   	/* Number of current processes */
	# __u16 pad;		   	/* Explicit padding for m68k */
	# __kernel_ulong_t totalhigh;	/* Total high memory size */
	# __kernel_ulong_t freehigh;	/* Available high memory size */
	# __u32 mem_unit;			/* Memory unit size in bytes */
	# char _f[20-2*sizeof(__kernel_ulong_t)-sizeof(__u32)];	/* Padding: libc5 uses this.. */
# };
bpf_text ="""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/sysinfo.h>
#include <uapi/linux/kernel.h>
int do_return(struct pt_regs *ctx, struct sysinfo *req) {
    struct sysinfo *sys;
    sys=req;
    bpf_trace_printk("t:%ld - f:%ld - s:%ld\\n",req->totalram<<(PAGE_SHIFT - 10),sys->freeram<<(PAGE_SHIFT - 10),sys->sharedram<<(PAGE_SHIFT - 10)); 
    return 0;    
}

"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="si_swapinfo", fn_name="do_return")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid,msg ))    
