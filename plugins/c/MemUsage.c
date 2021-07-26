#include <uapi/linux/ptrace.h>

int kprobe_wakeup_kswapd(struct pt_regs *ctx)
{
        bpf_trace_printk("Tracing for function of wakeup_kswapd...\\n");
        bpf_trace_printk("WARNING:A zone is low on free memory!\\n");

        return 0;
}