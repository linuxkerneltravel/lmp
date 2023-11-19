// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sysstat.h"

// 定义一个BPF映射，类型为BPF_MAP_TYPE_RINGBUF，最大条目数为1
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1);
} rb SEC(".maps");

// 定义一个kprobe钩子函数，钩住了内核函数get_page_from_freelist
SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist, gfp_t gfp_mask, unsigned int order, int alloc_flags, const struct alloc_context *ac)
{
	struct event *e; 
	unsigned long *t;

	// 在ring buffer中预留一块空间以存储事件数据
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// 从alloc_context结构中读取数据
    // e->present = BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat, node_spanned_pages);
	// 将读取到的数据填充到事件结构体中
	t = (unsigned long *)BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat, vm_stat);
    // t = (unsigned long *)BPF_CORE_READ(ac, preferred_zoneref, zone, vm_stat);
	e->anon_inactive = t[0]*4;  // 匿名页面不活跃
	e->anon_active = t[1]*4;    // 匿名页面活跃
	e->file_inactive = t[2]*4;  // 文件页面不活跃
	e->file_active = t[3]*4;    // 文件页面活跃
	e->unevictable = t[4]*4;    // 不可回收页面
       	

	e->file_dirty = t[20]*4;    // 脏文件页面
	e->writeback = t[21]*4;     // 正在回写的页面
	e->anon_mapped = t[17]*4;   // 匿名映射页面
	e->file_mapped = t[18]*4;   // 文件映射页面
	e->shmem = t[23]*4;         // 共享内存页面

	e->slab_reclaimable = t[5]*4;          // 可回收的slab页面
	e->kernel_misc_reclaimable = t[29]*4;  // 内核杂项可回收页面
	e->slab_unreclaimable = t[6]*4;        // 不可回收的slab页面

	e->unstable_nfs = t[27]*4;             // 不稳定的NFS页面
	e->writeback_temp = t[22]*4;           // 正在回写的临时页面

	e->anon_thps = t[26]*4;                // 匿名大页
	e->shmem_thps = t[24]*4;               // 共享内存大页
	e->pmdmapped = t[25]*4;                // 大页映射
	
	// 提交事件到ring buffer中
	bpf_ringbuf_submit(e, 0);
	return 0;
}

