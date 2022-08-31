// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
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


SEC("kprobe/finish_task_switch")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev)
{
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

