int hello_world(void *ctx)
{
    bpf_trace_printk("Hello, World!");
    return 0;
}