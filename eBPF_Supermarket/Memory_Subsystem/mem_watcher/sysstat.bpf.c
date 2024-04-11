
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
} last_val1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256 * 1024);
	__type(key, unsigned long);
	__type(value, int);
} last_val2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256 * 1024);
	__type(key, unsigned long);
	__type(value, int);
} last_val3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

pid_t user_pid = 0;


SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist_second, gfp_t gfp_mask, unsigned int order, int alloc_flags, const struct alloc_context *ac) {
	struct sysstat_event *e;
	unsigned long *t;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == user_pid)
		return 0;
	t = (unsigned long *)BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat, vm_stat);
	unsigned long anon_ina = t[0] * 4;
	unsigned long anon_mapped = t[17] * 4;
	unsigned long file_mapped = t[18] * 4;
	int val = 1;
	int *last_1, *last_2, *last_3;
	last_1 = bpf_map_lookup_elem(&last_val1, &anon_ina);
	last_2 = bpf_map_lookup_elem(&last_val2, &anon_mapped);
	last_3 = bpf_map_lookup_elem(&last_val3, &file_mapped);
	if (!last_1 || !last_2 || !last_3) {
		bpf_map_update_elem(&last_val1, &anon_ina, &val, BPF_ANY);
		bpf_map_update_elem(&last_val2, &anon_mapped, &val, BPF_ANY);
		bpf_map_update_elem(&last_val3, &file_mapped, &val, BPF_ANY);
	}
	else if ((*last_1 && *last_2 && *last_3) == val) {
		return 0;
	}
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	//	e->present = BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat, node_spanned_pages);
	//t = (unsigned long *)BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat, vm_stat);
	//	t = (unsigned long *)BPF_CORE_READ(ac, preferred_zoneref, zone, vm_stat);
	e->anon_inactive = t[0] * 4;
	e->anon_active = t[1] * 4;
	e->file_inactive = t[2] * 4;
	e->file_active = t[3] * 4;
	e->unevictable = t[4] * 4;


	e->file_dirty = t[20] * 4;
	e->writeback = t[21] * 4;
	e->anon_mapped = t[17] * 4;
	e->file_mapped = t[18] * 4;
	e->shmem = t[23] * 4;

	e->slab_reclaimable = t[5] * 4;
	e->kernel_misc_reclaimable = t[29] * 4;
	e->slab_unreclaimable = t[6] * 4;

	e->unstable_nfs = t[27] * 4;
	e->writeback_temp = t[22] * 4;

	e->anon_thps = t[26] * 4;
	e->shmem_thps = t[24] * 4;
	e->pmdmapped = t[25] * 4;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
