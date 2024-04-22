#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <linux/cpufreq.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* pmu_cyl, 一个perf_array, 用于读取CPU_CYCLES的计数值 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 64);
} pmu_cyl SEC(".maps");

/* pmu_clk, 一个perf_array, 用于读取CPU_CLOCK的计数值 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 64);
} pmu_clk SEC(".maps");

/* start_count，记录频率切换时的频率以及CYCLES和CLOCK的计数值 */
struct start_count {
    u32 prev_freq;
    u64 start_cyl;
    u64 start_clk;
};

/* start_info, 用于记录每个CPU在频率切换的信息 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct start_count));
    __uint(max_entries, 10000);
} start_info SEC(".maps");

/* dvfs_key, 充当Map的键, 字段为CPU和频段 */
struct dvfs_key {
    u32 cpu;
    u32 freq;
};

/* dvfs_value, 充当Map的值, 字段为此CPU在此频段的CPU_CYCLES和CPU_CLOCK计数值 */
struct dvfs_value {
    u64 cyl;
    u64 clk;
};

/* cpudvfs_info, 用于记录CPU在该阶段出现的频率相关信息 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct dvfs_key));
    __uint(value_size, sizeof(struct dvfs_value));
    __uint(max_entries, 10000);
} cpudvfs_info SEC(".maps");

/* cpufreq_freq_transition_end为频率切换工作完成后的通知函数 */
/* 可以通过第2个参数的new以及old和第三个参数判断是否进行了频率切换*/
SEC("kprobe/cpufreq_freq_transition_end")
int bpf_prog1(struct pt_regs *ctx)
{
    int failed = (int)PT_REGS_PARM3(ctx);
    if (failed) {
    	return 0;
    }

    u32 new, old;
    struct cpufreq_freqs *freqs = (struct cpufreq_freqs *)PT_REGS_PARM2(ctx);

    bpf_probe_read_kernel(&new, sizeof(new), &(freqs->new));
    bpf_probe_read_kernel(&old, sizeof(old), &(freqs->old));
    if (new == old) {
    	return 0;
    }
    
    /* 读取CPU ID 和 当前PMU计数值*/
    u32 cpu = bpf_get_smp_processor_id();

    u64 cyl = bpf_perf_event_read(&pmu_cyl, cpu);
    u64 clk = bpf_perf_event_read(&pmu_clk, cpu);

# if 0
    char fmt[] = "CYL: %u CLK: %u \n";
    bpf_trace_printk(fmt, sizeof(fmt), cyl, clk);
# endif
    
    struct start_count sc = {}, *scp;
    struct dvfs_key dk = {};
    struct dvfs_value dv = {}, *dvp;

    scp = bpf_map_lookup_elem(&start_info, &cpu);
    /* 没有之前的频率切换信息，只用更新本次切换信息 */
    if (scp == 0) {
        sc.prev_freq = new;
        sc.start_cyl = cyl;
        sc.start_clk = clk;

        bpf_map_update_elem(&start_info, &cpu, &sc, BPF_ANY);
        return 0;
    }
    /* 否则, 读取start_info, 填充cpudvfs_info, 更新本次切换信息 */
    dv.cyl = cyl - scp->start_cyl;
    dv.clk = cyl - scp->start_clk;

    dk.freq = scp->prev_freq;
    dk.cpu = cpu;

    dvp = bpf_map_lookup_elem(&cpudvfs_info, &dk);
    if (dvp) {
        dv.cyl += dvp->cyl;
        dv.clk += dvp->clk;
    }

    bpf_map_update_elem(&cpudvfs_info, &dk, &dv, BPF_ANY);

    scp->prev_freq = new;
    scp->start_cyl = cyl;
    scp->start_clk = clk;

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
