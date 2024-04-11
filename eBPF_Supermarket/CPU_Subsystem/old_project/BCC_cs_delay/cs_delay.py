from __future__ import print_function
from bcc import BPF
from time import sleep

# load BPF program
b = BPF(src_file="cs_delay.c")
b.attach_kprobe(event="schedule", fn_name="do_entry")
b.attach_kretprobe(event="schedule", fn_name="do_return")

print("Tracing for Data's... Ctrl-C to end")

# trace until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    print()

# output
b["dist"].print_log2_hist("cs delay")