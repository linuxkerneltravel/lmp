// +build ignore
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"


char __license[] SEC("license") = "Dual MIT/GPL";
const volatile u64 my_pid = 0;

struct bpf_map_def SEC("maps") kprobe_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};
struct buff_write_event_t {
	u32 pid;
	u64 offset;
	u64 bytes;
	u64 index;
	u64 pos;
	char filename[20];
	u64 ts;
} __attribute__((packed));

SEC("kprobe/ext4_da_write_begin")
int kprobe_prog(struct pt_regs *ctx) {

	struct file filp={};
    struct buff_write_event_t event = {};
	u64  id, pos;
	id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32; 
	if(my_pid != 0 ){
		if (pid != my_pid)
			return 0;
	}
	
	event.pid = pid;
	
    event.bytes = PT_REGS_PARM4(ctx);
	pos = PT_REGS_PARM3(ctx);
	event.pos = pos;
	event.index =  pos >> 13;
	event.offset = (pos & (4096 - 1));
	bpf_probe_read(&filp, sizeof(filp),(struct file *)PT_REGS_PARM1(ctx));
	event.ts = bpf_ktime_get_ns();
	bpf_probe_read(&event.filename, sizeof(event.filename),  filp.f_path.dentry->d_iname );
    bpf_perf_event_output(ctx, &kprobe_map, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}