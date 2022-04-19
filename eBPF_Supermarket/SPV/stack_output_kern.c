#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/perf_event.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>

struct key_t {
    u32 pid;
    u32 cpu;
};

struct val_t {
    char comm[TASK_COMM_LEN];
    u32 stack_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct key_t);
    __type(value, struct val_t);
    __uint(max_entries, 10000);
} task_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 10000);
} stackmap SEC(".maps");

#define STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)

SEC("kprobe/finish_task_switch")
int bpf_prog1(struct pt_regs *ctx, struct task_struct *prev)
{
    struct key_t key = {};
    struct val_t val = {};

    val.stack_id = bpf_get_stackid(ctx, &stackmap, STACKID_FLAGS);
    bpf_get_current_comm(&val.comm, sizeof(val.comm));

    key.pid = bpf_get_current_pid_tgid();
    key.cpu = bpf_get_smp_processor_id();

    bpf_map_update_elem(&task_info, &key, &val, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
