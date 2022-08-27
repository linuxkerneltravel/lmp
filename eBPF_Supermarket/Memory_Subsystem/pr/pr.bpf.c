// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "pr.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1);
} rb SEC(".maps");

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

