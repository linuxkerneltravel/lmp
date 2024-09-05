// Copyright 2024 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: luiyanbing@foxmail.com
//
// 内核态bpf的预读取分析模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ebpf.h"
#include "task.h"
#include "bpf_wapper/readahead.h"

#define MINBLOCK_US 1ULL
#define MAXBLOCK_US 99999999ULL

COMMON_MAPS(ra_tuple);
COMMON_VALS;

BPF_HASH(in_ra_map, u32, psid, MAX_ENTRIES/10);
BPF_HASH(page_psid_map, struct page *, psid, MAX_ENTRIES);

SEC("fentry/page_cache_ra_unbounded") // fentry在内核函数page_cache_ra_unbounded进入时触发的挂载点
int BPF_PROG(page_cache_ra_unbounded)
{
    CHECK_ACTIVE;
    CHECK_FREQ(TS);
    struct task_struct *curr = GET_CURR;
    CHECK_KTHREAD(curr);
    u32 tgid = BPF_CORE_READ(curr, tgid);
    CHECK_TGID(tgid);
    struct kernfs_node *knode = GET_KNODE(curr);
    CHECK_CGID(knode);

    u32 pid = BPF_CORE_READ(curr, pid);
    TRY_SAVE_INFO(curr, pid, tgid, knode);
    psid apsid = TRACE_AND_GET_COUNT_KEY(pid, ctx);
    ra_tuple *d = bpf_map_lookup_elem(&psid_count_map, &apsid); // d指向psid_count表中的apsid对应的类型为tuple的值
    if (!d)
    {
        ra_tuple a = {.expect = 0, .truth = 0};                    // 初始化为0
        bpf_map_update_elem(&psid_count_map, &apsid, &a, BPF_ANY); // 更新psid_count表中的apsid的值为a
    }
    bpf_map_update_elem(&in_ra_map, &pid, &apsid, BPF_ANY); // 更新in_ra表中的pid对应的值为apsid
    return 0;
}

SEC("fexit/alloc_pages") // fexit在内核函数alloc_pages退出时触发，挂载点为alloc_pages
int BPF_PROG(filemap_alloc_folio_ret, gfp_t gfp, unsigned int order, u64 ret)
{
    CHECK_ACTIVE;
    u32 pid = bpf_get_current_pid_tgid() >> 32;                 // pid为当前进程的pid
    struct psid *apsid = bpf_map_lookup_elem(&in_ra_map, &pid); // apsid指向了当前in_ra中pid的表项内容
    if (!apsid)
        return 0;

    ra_tuple *a = bpf_map_lookup_elem(&psid_count_map, apsid); // a是指向psid_count的apsid对应的内容
    if (!a)
        return 0;

    const u32 lim = 1ul << order; // 1 为长整型，左移order位，即2^order 即申请页的大小
    a->expect += lim;             // a->expect+=页大小（未访问）
    u64 addr;
    bpf_core_read(&addr, sizeof(u64), &ret); // alloc_pages返回的值，即申请页的起始地址保存在addr中
    for (int i = 0; i < lim && i < 1024; i++, addr += 0x1000)
        bpf_map_update_elem(&page_psid_map, &addr, apsid, BPF_ANY); // 更新page_psid表中的addr（从页的起始地址开始到页的结束地址）所对应的值为apsid

    return 0;
}

SEC("fexit/page_cache_ra_unbounded")
int BPF_PROG(page_cache_ra_unbounded_ret) // fexit在内核函数page_cache_ra_unbounded退出时触发的挂载点
{
    CHECK_ACTIVE;
    u32 pid = bpf_get_current_pid_tgid() >> 32; // 获取当前进程的pid
    bpf_map_delete_elem(&in_ra_map, &pid);      // 删除了in_ra对应的pid的表项,即删除对应的栈计数信息
    return 0;
}

SEC("fentry/mark_page_accessed") // fentry在内核函数/mark_page_accessed进入时触发的挂载点，用于标记页面（page）已经被访问
int BPF_PROG(mark_page_accessed, u64 page)
{
    CHECK_ACTIVE;
    u32 pid = bpf_get_current_pid_tgid() >> 32; // 获取当前进程的pid
    psid *apsid;
    apsid = bpf_map_lookup_elem(&page_psid_map, &page); // 查看page_psid对应的 地址page 对应类型为psid的值，并保存在apsid
    if (!apsid)
        return 0;
    ra_tuple *a = bpf_map_lookup_elem(&psid_count_map, apsid); // a指向psid_count的apsid的内容
    if (!a)
        return 0;
    a->truth++;                                 // 已访问
    bpf_map_delete_elem(&page_psid_map, &page); // 删除page_psid的page对应的内容
    return 0;
}

const char LICENSE[] SEC("license") = "GPL";