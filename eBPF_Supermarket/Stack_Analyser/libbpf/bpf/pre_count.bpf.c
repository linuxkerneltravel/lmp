// Copyright 2023 The LMP Authors.
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

#include "stack_analyzer.h"

#define MINBLOCK_US 1ULL
#define MAXBLOCK_US 99999999ULL

BPF_STACK_TRACE(stack_trace);
BPF_HASH(pid_tgid, u32, u32);
BPF_HASH(pid_comm, u32, comm);

BPF_HASH(psid_util, psid, tuple);

BPF_HASH(in_ra, u32, psid);
BPF_HASH(page_psid, struct page *, psid);

int apid = 0;
bool u = false, k = false;
__u64 min = 0, max = 0;

SEC("fentry/page_cache_ra_unbounded")
int BPF_PROG(page_cache_ra_unbounded)
{
    u64 td = bpf_get_current_pid_tgid();
    u32 pid = td >> 32;

    if ((apid >= 0 && pid != apid) || !pid)
        return 0;

    u32 tgid = td;
    bpf_map_update_elem(&pid_tgid, &pid, &tgid, BPF_ANY);
    comm *p = bpf_map_lookup_elem(&pid_comm, &pid);
    if (!p)
    {
        comm name;
        bpf_get_current_comm(&name, COMM_LEN);
        bpf_map_update_elem(&pid_comm, &pid, &name, BPF_NOEXIST);
    }
    psid apsid = {
        .pid = pid,
        .usid = u ? USER_STACK : -1,
        .ksid = k ? KERNEL_STACK : -1,
    };

    tuple *d = bpf_map_lookup_elem(&psid_util, &apsid);
    if (!d)
    {
        tuple a = {.expect = 0, .truth = 0};
        bpf_map_update_elem(&psid_util, &apsid, &a, BPF_ANY);
    }
    bpf_map_update_elem(&in_ra, &pid, &apsid, BPF_ANY);
    return 0;
}

SEC("fexit/alloc_pages")
int BPF_PROG(filemap_alloc_folio_ret, gfp_t gfp, unsigned int order, u64 ret)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if ((apid >= 0 && pid != apid) || !pid)
        return 0;

    struct psid *apsid = bpf_map_lookup_elem(&in_ra, &pid);
    if (!apsid)
        return 0;

    tuple *a = bpf_map_lookup_elem(&psid_util, apsid);
    if (!a)
        return 0;

    const u32 lim = 1ul << order;
    a->expect += lim;
    u64 addr;
    bpf_core_read(&addr, sizeof(u64), &ret);
    for (int i = 0; i < lim && i < 1024; i++, addr++)
        bpf_map_update_elem(&page_psid, &addr, apsid, BPF_ANY);

    return 0;
}

SEC("fexit/page_cache_ra_unbounded")
int BPF_PROG(page_cache_ra_unbounded_ret)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if ((apid >= 0 && pid != apid) || !pid)
        return 0;

    bpf_map_delete_elem(&in_ra, &pid);
    return 0;
}

SEC("fentry/mark_page_accessed")
int BPF_PROG(mark_page_accessed, u64 page)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if ((apid >= 0 && pid != apid) || !pid)
        return 0;
    psid *apsid;
    apsid = bpf_map_lookup_elem(&page_psid, &page);
    if (!apsid)
        return 0;
    tuple *a = bpf_map_lookup_elem(&psid_util, apsid);
    if (!a)
        return 0;
    a->truth++;
    bpf_map_delete_elem(&page_psid, &page);
    return 0;
}

const char LICENSE[] SEC("license") = "GPL";