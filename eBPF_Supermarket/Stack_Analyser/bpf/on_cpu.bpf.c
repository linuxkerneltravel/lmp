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
// 内核态bpf的on-cpu模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ebpf.h"
#include "task.h"

const char LICENSE[] SEC("license") = "GPL";

COMMON_MAPS(u32);
COMMON_VALS;

SEC("perf_event") // 挂载点为perf_event
int do_stack(void *ctx)
{
    CHECK_ACTIVE;
    struct task_struct *curr = GET_CURR; // curr指向当前进程的tsk
    CHECK_KTHREAD(curr);
    // perf 中已设置目标tgid，这里无需再次过滤tgid
    struct kernfs_node *knode = GET_KNODE(curr);
    CHECK_CGID(knode);

    u32 pid = BPF_CORE_READ(curr, pid);
    TRY_SAVE_INFO(curr, pid, BPF_CORE_READ(curr, tgid), knode);
    psid apsid = TRACE_AND_GET_COUNT_KEY(pid, ctx);
    u32 *count = bpf_map_lookup_elem(&psid_count_map, &apsid); // count指向psid_count对应的apsid的值
    if (count)
        (*count)++; // count不为空，则psid_count对应的apsid的值+1
    else
    {
        u32 orig = 1;
        bpf_map_update_elem(&psid_count_map, &apsid, &orig, BPF_ANY); // 否则psid_count对应的apsid的值=1
    }
    return 0;
}