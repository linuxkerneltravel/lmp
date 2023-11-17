// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

// 包含必要的头文件
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "pr.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义一个BPF映射，类型为BPF_MAP_TYPE_RINGBUF，最大条目数为1
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1);
} rb SEC(".maps");

// 定义一个kprobe钩子函数，钩住了内核函数shrink_page_list
SEC("kprobe/shrink_page_list")
int BPF_KPROBE(shrink_page_list, struct list_head *page_list, struct pglist_data *pgdat, struct scan_control *sc)
{
    struct event *e;
    unsigned long y;
    unsigned int *a;

    // 在ring buffer中预留一块空间以存储事件数据
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // 从scan_control结构中读取数据
    e->reclaim = BPF_CORE_READ(sc, nr_to_reclaim); // 需要回收的页面数
    y = BPF_CORE_READ(sc, nr_reclaimed); // 已经回收的页面数
    e->reclaimed = y;

    // 访问未回写的脏页、块设备上回写的页面和正在回写的页面的数量
    a = (unsigned int *)(&y + 1);
    e->unqueued_dirty = *(a + 1);
    e->congested = *(a + 2);
    e->writeback = *(a + 3);

    // 提交事件到ring buffer中
    bpf_ringbuf_submit(e, 0);
    return 0;
}
