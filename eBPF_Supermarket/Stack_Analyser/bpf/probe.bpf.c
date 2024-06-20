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
// probe功能的内核态bpf程序代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>

#include "ebpf.h"
#include "bpf_wapper/probe.h"
#include "task.h"

COMMON_MAPS(time_tuple);
COMMON_VALS;
BPF_HASH(starts, u32, u64, MAX_ENTRIES/10);

static int entry(void *ctx)
{
    CHECK_ACTIVE;
    u64 ts = bpf_ktime_get_ns();
    CHECK_FREQ(ts);
    struct task_struct *curr = GET_CURR;
    CHECK_KTHREAD(curr);
    u32 tgid = BPF_CORE_READ(curr, tgid);
    CHECK_TGID(tgid);
    struct kernfs_node *knode = GET_KNODE(curr);
    CHECK_CGID(knode);

    u32 pid = BPF_CORE_READ(curr, pid);
    TRY_SAVE_INFO(curr, pid, tgid, knode);
    bpf_map_update_elem(&starts, &pid, &ts, BPF_ANY);
    return 0;
}

static int exit(void *ctx)
{
    CHECK_ACTIVE;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *start = bpf_map_lookup_elem(&starts, &pid);
    if (!start)
        return 0;
    u64 delta = TS - *start;

    psid a_psid = TRACE_AND_GET_COUNT_KEY(pid, ctx);
    time_tuple *d = bpf_map_lookup_elem(&psid_count_map, &a_psid);
    if (!d)
    {
        time_tuple tmp = {.lat = delta, .count = 1};
        bpf_map_update_elem(&psid_count_map, &a_psid, &tmp, BPF_NOEXIST);
    }
    else
    {
        d->lat += delta;
        d->count++;
    }
    return 0;
}


SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe)
{
    entry(ctx);
    return 0;
}

SEC("kretprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe)
{
    exit(ctx);
    return 0;
}

SEC("fentry/dummy_fentry")
int BPF_PROG(dummy_fentry)
{
	entry(ctx);
	return 0;
}

SEC("fexit/dummy_fexit")
int BPF_PROG(dummy_fexit)
{
	exit(ctx);
	return 0;
}

static int static_tracing_handler(void *ctx)
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
    psid a_psid = TRACE_AND_GET_COUNT_KEY(pid, ctx);
    time_tuple *d = bpf_map_lookup_elem(&psid_count_map, &a_psid);
    if (!d)
    {
        time_tuple tmp = {.lat = 0, .count = 1};
        bpf_map_update_elem(&psid_count_map, &a_psid, &tmp, BPF_NOEXIST);
    }
    else
        d->count++;
    return 0;
}

SEC("tp/sched/dummy_tp")
int tp_exit(void *ctx)
{
    static_tracing_handler(ctx);
    return 0;
}

SEC("usdt")
int usdt_exit(void *ctx)
{
    static_tracing_handler(ctx);
    return 0;
}

const char LICENSE[] SEC("license") = "GPL";