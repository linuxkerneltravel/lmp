// +build ignore
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct ext4_write_event_t {
	u32 pid;
 	u32 type;
 	u32 iov_offset;
	u32 count;
 	u64	pos;
 	u64	flags;
 	u16	hint;
 	u16	ioprio;
	u32	cookie;
}__attribute__((packed));
struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

struct bpf_map_def SEC("maps") pidfor_user = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1,
};

SEC("kprobe/ext4_file_write_iter")
int kprobe_ext4_file_write_iter(struct pt_regs *ctx) {
	struct ext4_write_event_t event = {};
	u64  id;
	u32 *test_pid;
	id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32; 
	u32 key = 0;
    struct kiocb *iocbx = (struct kiocb *)PT_REGS_PARM1(ctx);
	if(iocbx == NULL)
	{
		return 0;
	}
    struct iov_iter *fromx = (struct iov_iter *)PT_REGS_PARM2(ctx);
	if(fromx == NULL)
	{
		return 0;
	}
	test_pid = bpf_map_lookup_elem(&pidfor_user,&key);
	if(test_pid == NULL)
		return 0;
	if ((*test_pid) != 0)
	{
		if(pid != (*test_pid))
			return 0;
	}
	event.pid =pid;
	bpf_probe_read_kernel(&(event.type),sizeof(u32),&(fromx->type));
	bpf_probe_read_kernel(&(event.iov_offset),sizeof(u32),&(fromx->iov_offset));
	bpf_probe_read_kernel(&(event.count),sizeof(u32),&(fromx->count));

	bpf_probe_read_kernel(&(event.pos),sizeof(u32),&(iocbx->ki_pos));
	bpf_probe_read_kernel(&(event.flags),sizeof(u32),&(iocbx->ki_flags));
	bpf_probe_read_kernel(&(event.hint),sizeof(u32),&(iocbx->ki_hint));
	bpf_probe_read_kernel(&(event.ioprio),sizeof(u32),&(iocbx->ki_ioprio));
	bpf_probe_read_kernel(&(event.cookie),sizeof(u32),&(iocbx->ki_cookie));

	bpf_perf_event_output(ctx,&events,BPF_F_CURRENT_CPU,&event,sizeof(event));
	return 0;
}