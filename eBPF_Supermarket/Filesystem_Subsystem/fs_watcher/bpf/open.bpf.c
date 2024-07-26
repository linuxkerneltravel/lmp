#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 100
#define path_size 256

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, char[TASK_COMM_LEN]);
} data SEC(".maps");

struct event {
	int pid_;
	char path_name_[path_size];
	int n_;
    char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps"); // 环形缓冲区


SEC("tracepoint/syscalls/sys_enter_openat")
int do_syscall_trace(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm,sizeof(comm));
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	char filename[path_size];
	struct task_struct *task = (struct task_struct *)bpf_get_current_task(),
			   *real_parent;
	if (task == NULL) {
		bpf_printk("task\n");
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	int pid = bpf_get_current_pid_tgid() >> 32, tgid;

    bpf_map_update_elem(&data, &pid, &comm, BPF_ANY);

	int ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_probe_read_str(e->path_name_, sizeof(e->path_name_),
			   (void *)(ctx->args[1]));

	bpf_printk("path name: %s,pid:%d,ppid:%d\n", e->path_name_, pid, ppid);

	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (fdt == NULL) {
		bpf_printk("fdt\n");
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	unsigned int i = 0, count = 0, n = BPF_CORE_READ(fdt, max_fds);
	bpf_printk("n:%d\n", n);

	e->n_ = n;
	e->pid_ = pid;

	bpf_ringbuf_submit(e, 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";