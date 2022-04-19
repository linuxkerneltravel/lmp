#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include <linux/ptrace.h>

struct bpf_map_def SEC("maps") l3_miss_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.key_size	= sizeof(u32),
	.value_size	= sizeof(unsigned long),
	.max_entries	= 100000,
};

struct bpf_map_def SEC("maps") qpi_data_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.key_size	= sizeof(u32),
	.value_size	= sizeof(unsigned long),
	.max_entries	= 100000,
};

struct bpf_map_def SEC("maps") imc_reads_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.key_size	= sizeof(u32),
	.value_size	= sizeof(unsigned long),
	.max_entries	= 100000,
};

SEC("kretprobe/total_l3_cache_misses")
int bpf_prog0(struct pt_regs *ctx)
{
	unsigned long total_misses = PT_REGS_RC(ctx);
	u32 cpu_id = bpf_get_smp_processor_id();
	
	bpf_map_update_elem(&l3_miss_map, &cpu_id, &total_misses, BPF_ANY);
	
	return 0;
}

SEC("kretprobe/total_data_from_qpi")
int bpf_prog1(struct pt_regs *ctx)
{
	unsigned long total_qpi_data = PT_REGS_RC(ctx);
	u32 cpu_id = bpf_get_smp_processor_id();
	
	bpf_map_update_elem(&qpi_data_map, &cpu_id, &total_qpi_data, BPF_ANY);
	
	return 0;
}

SEC("kretprobe/total_qmc_normal_reads_any")
int bpf_prog2(struct pt_regs *ctx)
{
	unsigned long total_imc_read = PT_REGS_RC(ctx);
	u32 cpu_id = bpf_get_smp_processor_id();
	
	bpf_map_update_elem(&imc_reads_map, &cpu_id, &total_imc_read, BPF_ANY);
	
	return 0;
}

char _license[] SEC("license") = "GPL";
