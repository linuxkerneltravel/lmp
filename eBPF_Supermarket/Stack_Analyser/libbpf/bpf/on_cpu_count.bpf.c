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
// 内核态bpf的on-cpu模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "stack_analyzer.h"

const char LICENSE[] SEC("license") = "GPL";

BPF_STACK_TRACE(stack_trace);
BPF_HASH(pid_tgid, u32, u32);
BPF_HASH(psid_count, psid, u32);
BPF_HASH(pid_comm, u32, comm);

bool u, k;
__u64 min, max;
unsigned long *load_a;

SEC("perf_event")
int do_stack(void *ctx)
{
    unsigned long load;
    bpf_core_read(&load, sizeof(unsigned long), load_a);
    load >>= 11;
    bpf_printk("%lu %lu", load, min);
    if (load < min || load > max)
        return 0;

    // record data
    struct task_struct *curr = (void *)bpf_get_current_task();
    u32 pid = BPF_CORE_READ(curr, pid);
    if (!pid)
        return 0;
    u32 tgid = BPF_CORE_READ(curr, tgid);
    bpf_map_update_elem(&pid_tgid, &pid, &tgid, BPF_ANY);
    comm *p = bpf_map_lookup_elem(&pid_comm, &pid);
    if (!p)
    {
        comm name;
        bpf_probe_read_kernel_str(&name, COMM_LEN, curr->comm);
        bpf_map_update_elem(&pid_comm, &pid, &name, BPF_NOEXIST);
    }
    psid apsid = {
        .pid = pid,
        .usid = u ? USER_STACK : -1,
        .ksid = k ? KERNEL_STACK : -1,
    };

    // add cosunt
    u32 *count = bpf_map_lookup_elem(&psid_count, &apsid);
    if (count)
        (*count)++;
    else
    {
        u32 orig = 1;
        bpf_map_update_elem(&psid_count, &apsid, &orig, BPF_ANY);
    }
    return 0;
}