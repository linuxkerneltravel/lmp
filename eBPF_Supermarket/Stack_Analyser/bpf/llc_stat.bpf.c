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

#include "sa_ebpf.h"
#include "bpf_wapper/llc_stat.h"
#include "task.h"

COMMON_MAPS(llc_stat);
COMMON_VALS;

static __always_inline int trace_event(__u64 sample_period, bool miss, struct bpf_perf_event_data *ctx)
{
    CHECK_ACTIVE;
    CHECK_FREQ;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

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
    psid apsid = GET_COUNT_KEY(pid, ctx);
    llc_stat *infop = bpf_map_lookup_elem(&psid_count_map, &apsid);
    if (!infop)
    {
        llc_stat tmp = {miss, !miss};
        bpf_map_update_elem(&psid_count_map, &apsid, &tmp, BPF_NOEXIST);
    }
    else
    {
        if (miss)
            infop->miss++;
        else
            infop->ref++;
    }
    return 0;
}

SEC("perf_event")
int on_cache_miss(struct bpf_perf_event_data *ctx)
{
    return trace_event(ctx->sample_period, true, ctx);
}

SEC("perf_event")
int on_cache_ref(struct bpf_perf_event_data *ctx)
{
    return trace_event(ctx->sample_period, false, ctx);
}

const char LICENSE[] SEC("license") = "GPL";