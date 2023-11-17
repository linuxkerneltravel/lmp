// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

// 包含必要的头文件
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "procstat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义一个BPF映射，类型为BPF_MAP_TYPE_RINGBUF，最大条目数为256 * 1024
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");


// 定义一个kprobe钩子函数，钩住了内核函数finish_task_switch
SEC("kprobe/finish_task_switch")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev)
{
	struct event *e;
	struct mm_rss_stat rss = {};  // 定义一个mm_rss_stat结构体
	struct mm_struct *mms;
	long long *t;

      // 在ring buffer中预留一块空间以存储事件数据
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

    // 从prev任务的mm_struct中读取数据
	e->pid = BPF_CORE_READ(prev, pid);            // 进程ID
	e->vsize = BPF_CORE_READ(prev, mm, total_vm); // 虚拟内存大小
	e->Vdata = BPF_CORE_READ(prev, mm, data_vm);  // 数据段的大小
	e->Vstk = BPF_CORE_READ(prev, mm, stack_vm);  // 栈的大小
	e->nvcsw = BPF_CORE_READ(prev, nvcsw);        // 非自愿上下文切换次数
	e->nivcsw = BPF_CORE_READ(prev, nivcsw);      // 自愿上下文切换次数

    // 读取rss_stat结构体中的数据
	rss = BPF_CORE_READ(prev, mm, rss_stat);      // 从mm_struct中获取rss_stat结构体
	t = (long long *)(rss.count);
	e->rssfile = *t;                              // 文件页表占用的页面数
	e->rssanon = *(t + 1);                        // 匿名页表占用的页面数
	e->vswap = *(t + 2);                          // 虚拟内存交换区占用的页面数
	e->rssshmem = *(t + 3);                       // 共享内存占用的页面数
	e->size = *t + *(t + 1) + *(t + 3);           // 总的物理内存占用的页面数

    // 提交事件到ring buffer中
	bpf_ringbuf_submit(e, 0);
	return 0;
}