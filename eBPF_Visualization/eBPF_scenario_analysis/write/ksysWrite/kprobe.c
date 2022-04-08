// +build ignore

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};
struct ksys_write_event_t {
	u32 pid;
	u32 count;
	u32 fd;
	u64 ts;
	char buf[20];
} __attribute__((packed));

SEC("kprobe/ksys_write")
int kprobe_execve(struct pt_regs *ctx) {

	int my_pid;
    asm("%0 = MY_PID ll" : "=r"(my_pid));

    struct ksys_write_event_t event = {};
	u64  id;
	id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32; 
	if(my_pid != 0 ){
		if (pid != my_pid)
			return 0;
	}
	
	event.pid = pid;
    event.fd = PT_REGS_PARM1(ctx);
    char *filename = (char *)PT_REGS_PARM2(ctx);
	event.count = PT_REGS_PARM3(ctx);
	event.ts = bpf_ktime_get_ns();
	bpf_probe_read(&event.buf, sizeof(event.buf), filename);
    bpf_perf_event_output(ctx, &kprobe_map, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}