from __future__ import print_function
from bcc import BPF
from time import sleep
import argparse

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cpufreq.h>

// BPF_HASH(freq_cpu, u32, u32);

int do_cpufreq_ts(struct pt_regs *ctx, struct cpufreq_policy *policy, struct cpufreq_freqs *freqs, int transition_failed)
{
    if (transition_failed) {
        return 0;
    }

    u32 cpu = bpf_get_smp_processor_id();
    u32 freq_new = freqs->new;
    u32 freq_old = freqs->old;

    if (freq_new == freq_old)
        return 0;

    bpf_trace_printk("CPU: %d  OLD: %d ---> NEW: %d\\n", cpu, freq_old, freq_new);

    // freq_cpu.update(&cpu, &freq_new);

    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="cpufreq_freq_transition_end", fn_name="do_cpufreq_ts")

#freq_cpu = b.get_table("freq_cpu")

#while (1):
#    sleep(1)
#    for k, v in freq_cpu.items():
#        print(k.value, v.value)
#    print("====")

try:
    b.trace_print()
except KeyboardInterrupt:
    pass
