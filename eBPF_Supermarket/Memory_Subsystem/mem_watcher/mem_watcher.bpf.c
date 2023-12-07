#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mem_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist, gfp_t gfp_mask, unsigned int order, int alloc_flags, const struct alloc_context *ac)
{
	struct event *e; 
	unsigned long *t, y;
	int a;

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

SEC("kprobe/shrink_page_list")
int BPF_KPROBE(shrink_page_list, struct list_head *page_list, struct pglist_data *pgdat, struct scan_control *sc)
{
	struct event *e; 
	unsigned long y;
	unsigned int *a;

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

SEC("kprobe/finish_task_switch")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev) {
	struct event *e;
	struct mm_rss_stat rss = {};
	struct mm_struct *mms;
	long long *t;

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

SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist_second, gfp_t gfp_mask, unsigned int order, int alloc_flags, const struct alloc_context *ac) {
	struct event *e;
	unsigned long *t;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	//	e->present = BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat, node_spanned_pages);
	t = (unsigned long *)BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat, vm_stat);
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
