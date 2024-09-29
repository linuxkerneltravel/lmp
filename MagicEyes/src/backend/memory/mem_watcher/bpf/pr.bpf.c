
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
#include "mem_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256 * 1024);
	__type(key, unsigned long);
	__type(value, int);
} last_val SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

pid_t user_pid = 0;

SEC("kprobe/shrink_page_list")
int BPF_KPROBE(shrink_page_list, struct list_head *page_list, struct pglist_data *pgdat, struct scan_control *sc)
{
	struct pr_event *e;
	unsigned long y;
	unsigned int *a;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == user_pid)
		return 0;

	int val = 1;
	unsigned long rec = BPF_CORE_READ(sc, nr_reclaimed);
	int *last_rec;
	last_rec = bpf_map_lookup_elem(&last_val, &rec);
	if (!last_rec) {
		bpf_map_update_elem(&last_val, &rec, &val, BPF_ANY);
	}
	else if(*last_rec == val) {
		return 0;
	}

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->reclaim = BPF_CORE_READ(sc, nr_to_reclaim);//要回收页面
	y = BPF_CORE_READ(sc, nr_reclaimed);
	e->reclaimed = y;//已经回收的页面
	a =(unsigned int *)(&y + 1);
	e->unqueued_dirty = *(a + 1);//还没开始回写和还没在队列等待的脏页
	e->congested = *(a + 2);//正在块设备上回写的页面，含写入交换空间的页面
	e->writeback = *(a + 3);//正在回写的页面
	
	bpf_ringbuf_submit(e, 0);
	return 0; 
}