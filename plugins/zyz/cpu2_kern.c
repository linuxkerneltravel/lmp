#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <linux/cpufreq.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 64);
} pmu_cyl SEC(".maps");

struct freq_ts {
    u32 prev_freq;
    u64 start;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct freq_ts));
    __uint(max_entries, 64);
} start SEC(".maps");

SEC("kprobe/cpufreq_freq_transition_end")
int bpf_prog1(struct pt_regs *ctx)
{
    struct cpufreq_freqs *freqs = (struct cpufreq_freqs *)PT_REGS_PARM2(ctx);
    int failed = (int)PT_REGS_PARM3(ctx);

    if (failed) {
    	return 0;
    }

    u32 new, old;
    bpf_probe_read_kernel(&new, sizeof(new), &(freqs->new));
    bpf_probe_read_kernel(&old, sizeof(old), &(freqs->old));

    if (new == old) {
    	return 0;
    }
    
    u64 ts = bpf_ktime_get_ns(), delta;
    u32 cpu = bpf_get_smp_processor_id();
    struct freq_ts ft = {}, *ftp;

    ftp = bpf_map_lookup_elem(&start, &cpu);
    if (ftp == 0) {
    	ft.prev_freq = new;
	ft.start = ts;

	bpf_map_update_elem(&start, &cpu, &ft, BPF_ANY);
	return 0;
    }

    delta = ts - ftp->start;
    ftp->prev_freq = new;
    ftp->start = ts;

    u64 cyl = bpf_perf_event_read(&pmu_cyl, cpu);
    u64 util = cyl * 10000 / (delta * old);
    char fmt[] = "freq: %u time: %u util: %u%%\n";

    bpf_trace_printk(fmt, sizeof(fmt),  old, delta, util);

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;

