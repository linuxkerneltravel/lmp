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
// 内核态bpf的off-cpu模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ebpf.h"
#include "task.h"

COMMON_MAPS(u32);
COMMON_VALS;
// 记录进程运行的起始时间
BPF_HASH(pid_offTs_map, u32, u64, MAX_ENTRIES/10);

const char LICENSE[] SEC("license") = "GPL";

static int prev_part(struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    CHECK_FREQ(ts);
    CHECK_KTHREAD(prev);
    u32 tgid = BPF_CORE_READ(prev, tgid);
    CHECK_TGID(tgid);
    struct kernfs_node *knode = GET_KNODE(prev);
    CHECK_CGID(knode);
    u32 pid = BPF_CORE_READ(prev, pid);
    bpf_map_update_elem(&pid_offTs_map, &pid, &ts, BPF_ANY);
    return 0;
}

static int next_part(struct task_struct *next, void *ctx)
{
    // 利用帮助函数获取next指向的tsk的pid
    u32 pid = BPF_CORE_READ(next, pid);
    // tsp指向start表中的pid的值
    u64 *tsp = bpf_map_lookup_elem(&pid_offTs_map, &pid);
    if (!tsp)
        return 0;
    // delta为当前时间戳 - 原先tsp指向start表中的pid的值.代表运行时间
    u32 delta = (bpf_ktime_get_ns() - *tsp) >> 20;
    if (!delta)
        return 0;

    // record data
    struct kernfs_node *knode = GET_KNODE(next);
    TRY_SAVE_INFO(next, pid, BPF_CORE_READ(next, tgid), knode);
    psid apsid = TRACE_AND_GET_COUNT_KEY(pid, ctx);

    // record time delta
    // count指向psid_count中的apsid对应的值
    u32 *count = bpf_map_lookup_elem(&psid_count_map, &apsid);
    if (count)
        // 如果count存在，则psid_count中的apsid对应的值+=时间戳
        (*count) += delta;
    else
        // 如果不存在，则将psid_count表中的apsid设置为delta
        bpf_map_update_elem(&psid_count_map, &apsid, &delta, BPF_NOEXIST);
    return 0;
}

// 动态挂载点finish_task_switch.isra.0
SEC("kprobe/finish_task_switch")
int BPF_KPROBE(do_stack, struct task_struct *prev)
{
    CHECK_ACTIVE;
    prev_part(prev);
    // calculate time delta, next ready to run
    next_part(GET_CURR, ctx);
    return 0;
}