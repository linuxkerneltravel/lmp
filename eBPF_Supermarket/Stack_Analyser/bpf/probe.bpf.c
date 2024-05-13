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
// 内核态bpf程序的模板代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>

#include "sa_ebpf.h"
#include "bpf_wapper/probe.h"
#include "task.h"

COMMON_MAPS(time_tuple);
COMMON_VALS;
BPF_HASH(starts, u32, u64);

static int entry(void *ctx)
{
    CHECK_ACTIVE;
    CHECK_FREQ;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task(); // 利用bpf_get_current_task()获得当前的进程tsk

    if (BPF_CORE_READ(curr, flags) & PF_KTHREAD)
        return 0;
    u32 pid = BPF_CORE_READ(curr, pid); // 利用帮助函数获得当前进程的pid
    if ((!pid) || (pid == self_pid) || (target_pid > 0 && pid != target_pid))
        return 0;
    if (target_tgid > 0 && BPF_CORE_READ(curr, tgid) != target_tgid)
        return 0;
    SET_KNODE(curr, knode);
    if (target_cgroupid > 0 && BPF_CORE_READ(knode, id) != target_cgroupid)
        return 0;

    SAVE_TASK_INFO(pid, curr, knode);

    u64 nsec = bpf_ktime_get_ns();
    bpf_map_update_elem(&starts, &pid, &nsec, BPF_ANY);
    return 0;
}

SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe)
{
    entry(ctx);
    return 0;
}

static int exit(void *ctx)
{
    CHECK_ACTIVE;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u64 *start = bpf_map_lookup_elem(&starts, &pid);
    if (!start)
        return 0;

    u64 delta = bpf_ktime_get_ns() - *start;

    psid a_psid = GET_COUNT_KEY(pid, ctx);
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

SEC("kretprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe)
{
    exit(ctx);
    return 0;
}


static int handleCounts(void *ctx)
{
    CHECK_ACTIVE;
    u32 pid = bpf_get_current_pid_tgid() >> 32;


    psid a_psid = GET_COUNT_KEY(pid, ctx);
    time_tuple *d = bpf_map_lookup_elem(&psid_count_map, &a_psid);
    if (!d)
    {
        time_tuple tmp = {.lat = 0, .count = 1};
        bpf_map_update_elem(&psid_count_map, &a_psid, &tmp, BPF_NOEXIST);
    }
    else
    {
        d->lat = 0;
        d->count++;
    }
    return 0;
}
SEC("tp/sched/dummy_tp")
int tp_exit(void *ctx)
{
    handleCounts(ctx);
    return 0;
}
SEC("usdt")
int usdt_exit(void *ctx)
{
    handleCounts(ctx);
    return 0;
}
const char LICENSE[] SEC("license") = "GPL";