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
#include "paf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

pid_t user_pid = 0;

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1);
} rb SEC(".maps");

SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist, gfp_t gfp_mask, unsigned int order, int alloc_flags, const struct alloc_context *ac)
{
	struct event *e;
	unsigned long *t, y;
	int a;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == user_pid)
		return 0;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	y = BPF_CORE_READ(ac, preferred_zoneref, zone, watermark_boost);
	t = BPF_CORE_READ(ac, preferred_zoneref, zone, _watermark);

	e->present = BPF_CORE_READ(ac, preferred_zoneref, zone, present_pages);
	e->min = t[0] + y;
	e->low = t[1] + y;
	e->high = t[2] + y;
	e->flag = (int)gfp_mask;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
