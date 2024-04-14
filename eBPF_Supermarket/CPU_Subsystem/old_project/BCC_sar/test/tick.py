#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF

bpf = BPF(src_file="tick.c")
bpf.attach_kprobe(event="account_process_tick", fn_name="account_process_tick")
bpf.attach_kprobe(event="account_user_time", fn_name="account_user_time")
bpf.attach_kprobe(event="account_idle_ticks", fn_name="account_idle_ticks")
bpf.attach_kprobe(event="account_system_time", fn_name="account_system_time")
bpf.trace_print()