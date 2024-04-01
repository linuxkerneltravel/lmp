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
// author: GaoYixiang
//
// 内核态eBPF的通用的调用栈计数代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "sa_ebpf.h"
#include "task.h"

COMMON_MAPS(u32);
COMMON_VALS;
const volatile int target_pid = 0;

const char LICENSE[] SEC("license") = "GPL";

static int handle_func(void *ctx)
{
    CHECK_ACTIVE;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task(); // 利用bpf_get_current_task()获得当前的进程tsk
    RET_IF_KERN(curr);

    u32 pid = get_task_ns_pid(curr); // 利用帮助函数获得当前进程的pid
    if ((target_pid >= 0 && pid != target_pid) || !pid || pid == self_pid)
        return 0;

    SAVE_TASK_INFO(pid, curr);

    psid a_psid = GET_COUNT_KEY(pid, ctx);
    u32 *cnt = bpf_map_lookup_elem(&psid_count_map, &a_psid);
    if (!cnt)
    {
        u32 ONE = 1;
        bpf_map_update_elem(&psid_count_map, &a_psid, &ONE, BPF_NOEXIST);
    }
    else
        (*cnt)++;

    return 0;
}

SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(handle)
{
    handle_func(ctx);
    return 0;
}
SEC("tp/sched/dummy_tp")
int handle_tp(void *ctx)
{
    handle_func(ctx);
    return 0;
}