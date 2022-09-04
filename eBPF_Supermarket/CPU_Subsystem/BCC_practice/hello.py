#!/usr/bin/env python3
# 1) import bcc library
from bcc import BPF

# 2) load BPF program
b = BPF(src_file="hello.c")

# 3) attach kprobe
b.attach_kprobe(event="schedule", fn_name="hello_world")

# 4) read and print /sys/kernel/debug/tracing/trace_pipe
# 在使用之前，需要将trace打开
# echo 1 > /sys/kernel/tracing/tracing_on
b.trace_print()