#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "cpu.h"
#include "io.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define IO_MAX_ENTRIES 10240

BPF_HASH(io_stats, __u32, struct io_stat, IO_MAX_ENTRIES);

SEC("tracepoint/syscalls/sys_exit_read")
int handle_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	long ret = ctx->ret;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct io_stat *st = bpf_map_lookup_elem(&io_stats, &pid);
	if (!st) {
		struct io_stat zero = {};
		bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
		bpf_map_update_elem(&io_stats, &pid, &zero, BPF_ANY);
		st = bpf_map_lookup_elem(&io_stats, &pid);
		if (!st)
			return 0;
	}
	if (ret >= 0)
		st->read_calls += 1;
	if (ret > 0)
		st->read_bytes += (__u64)ret;
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int handle_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	long ret = ctx->ret;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct io_stat *st = bpf_map_lookup_elem(&io_stats, &pid);
	if (!st) {
		struct io_stat zero = {};
		bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
		bpf_map_update_elem(&io_stats, &pid, &zero, BPF_ANY);
		st = bpf_map_lookup_elem(&io_stats, &pid);
		if (!st)
			return 0;
	}
	if (ret >= 0)
		st->write_calls += 1;
	if (ret > 0)
		st->write_bytes += (__u64)ret;
	return 0;
} 