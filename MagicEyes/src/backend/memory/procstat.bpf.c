
/* 请一定注意vmlinux.h头文件是依赖于特定架构的，本机编译的时候需要自行生成，
生成方法：
1、切换至本代码../../vmlinux/你的架构目录下；
2、安装Linux开发工具包：sudo apt install linux-tools-$(uname -r)
3、删除那个vmlinux_数字.h文件（记住它的名字）；
4、生成vmlinux.h文件：bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
5、将生成的vmlinux.h文件名字改成刚刚删除的vmlinux_数字.h
如果编译不通过，提示找不到vmlinux.h文件，那么请在本代码同级目录下运行生成vmlinux.h命令 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "procstat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

pid_t user_pid = 0;


SEC("kprobe/finish_task_switch")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev) {
	struct procstat_event *e;
	struct mm_rss_stat rss = {};
	struct mm_struct *mms;
	long long *t;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == user_pid)
		return 0;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = BPF_CORE_READ(prev, pid);
	e->vsize = BPF_CORE_READ(prev, mm, total_vm);
	e->Vdata = BPF_CORE_READ(prev, mm, data_vm);
	e->Vstk = BPF_CORE_READ(prev, mm, stack_vm);
	e->nvcsw = BPF_CORE_READ(prev, nvcsw);
	e->nivcsw = BPF_CORE_READ(prev, nivcsw);

	rss = BPF_CORE_READ(prev, mm, rss_stat);
	t = (long long *)(rss.count);
	e->rssfile = *t;
	e->rssanon = *(t + 1);
	e->vswap = *(t + 2);
	e->rssshmem = *(t + 3);
	e->size = *t + *(t + 1) + *(t + 3);

	bpf_ringbuf_submit(e, 0);
	return 0;
}