int kprobe__schedule(void *ctx) {
    bpf_trace_printk("schedule() called.\n");
    return 0;
}