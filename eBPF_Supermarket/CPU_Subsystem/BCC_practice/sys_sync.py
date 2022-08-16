from bcc import BPF

with open("sys_sync.c", "r") as f:
    txt = f.read()
bpf = BPF(text=txt)
bpf.trace_print()