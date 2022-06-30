// +build ignore
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

#define PERF_MAX_STACK_DEPTH         127
struct intr_message
{
    unsigned long vector;
    u32 pid;
    u32 stack_id;
};
struct bpf_map_def SEC("maps") stack_traces = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(u32),
	.value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
	.max_entries = 10000,
};
struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 1<<24,
};


SEC("kprobe/do_error_trap")
int kprobe__do_error_trap(struct pt_regs *ctx)
{   
    struct intr_message *intr_mess;
    unsigned long trapnr = PT_REGS_PARM4(ctx);
    u32 pid = bpf_get_current_pid_tgid()>>32;
    intr_mess = bpf_ringbuf_reserve(&events, sizeof(struct intr_message), 0);
	if (!intr_mess) {
		return 0;
	}
    intr_mess->stack_id = bpf_get_stackid(ctx,&stack_traces,0);
    intr_mess->pid = pid;
	intr_mess ->vector = trapnr;
	bpf_ringbuf_submit(intr_mess, 0);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
