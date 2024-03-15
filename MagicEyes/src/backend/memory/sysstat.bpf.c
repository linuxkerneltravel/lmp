// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sysstat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1);
} rb SEC(".maps");

SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist, gfp_t gfp_mask, unsigned int order, int alloc_flags, const struct alloc_context *ac)
{
	struct event *e; 
	unsigned long *t;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

//	e->present = BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat, node_spanned_pages);
	t = (unsigned long *)BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat, vm_stat);
//	t = (unsigned long *)BPF_CORE_READ(ac, preferred_zoneref, zone, vm_stat);
	e->anon_inactive = t[0]*4;
	e->anon_active = t[1]*4;
	e->file_inactive = t[2]*4;
	e->file_active = t[3]*4;
	e->unevictable = t[4]*4;
       	

	e->file_dirty = t[20]*4;
	e->writeback = t[21]*4;
	e->anon_mapped = t[17]*4;
	e->file_mapped = t[18]*4;
	e->shmem = t[23]*4;

	e->slab_reclaimable = t[5]*4;
	e->kernel_misc_reclaimable = t[29]*4;
	e->slab_unreclaimable = t[6]*4;

	e->unstable_nfs = t[27]*4;
	e->writeback_temp = t[22]*4;

	e->anon_thps = t[26]*4;
	e->shmem_thps = t[24]*4;
	e->pmdmapped = t[25]*4;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

