#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF

bpf = BPF(src_file="wakeup.c")
bpf.attach_tracepoint(tp="sched:sched_wakeup", fn_name="trace_wakeup")
bpf.attach_tracepoint(tp="sched:sched_process_wait", fn_name="trace_wait")
bpf.attach_tracepoint(tp="sched:sched_stat_blocked",fn_name="trace_block")
bpf.trace_print()