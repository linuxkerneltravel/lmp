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
// 内核态bpf的off-cpu模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "stack_analyzer.h"

#define MINBLOCK_US 1ULL
#define MAXBLOCK_US 99999999ULL

BPF_HASH(psid_count, psid, u32);
BPF_HASH(start, u32, u64);
BPF_STACK_TRACE(stack_trace);
BPF_HASH(pid_tgid, u32, u32);
BPF_HASH(pid_comm, u32, comm);

const char LICENSE[] SEC("license") = "GPL";

int apid;
char u,k;

SEC("kprobe/finish_task_switch.isra.0")
int BPF_KPROBE(do_stack, struct task_struct *curr)
{
    u32 pid = BPF_CORE_READ(curr, pid);

    if((apid >= 0 && pid != apid) || !pid)
        return 0;

    // record next start time
    u32 tgid = BPF_CORE_READ(curr, tgid);
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_NOEXIST);

    // calculate time delta
    struct task_struct *next = (struct task_struct *)bpf_get_current_task();
    pid = BPF_CORE_READ(next, pid);
    u64 *tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp)
        return 0;
    bpf_map_delete_elem(&start, &pid);
    u32 delta = (bpf_ktime_get_ns() - *tsp) >> 20;

    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US))
        return 0;

    // record data
    tgid = BPF_CORE_READ(next, tgid);
    bpf_map_update_elem(&pid_tgid, &pid, &tgid, BPF_ANY);
    comm *p = bpf_map_lookup_elem(&pid_comm, &pid);
    if (!p)
    {
        comm name;
        bpf_probe_read_kernel_str(&name, TASK_COMM_LEN, next->comm);
        bpf_map_update_elem(&pid_comm, &pid, &name, BPF_NOEXIST);
    }
    psid apsid = {
        .pid = pid,
        .usid = u?USER_STACK:-1,
        .ksid = k?KERNEL_STACK:-1,
    };

    // record time delta
    u32 *count = bpf_map_lookup_elem(&psid_count, &apsid);
    if (count)
        (*count) += delta;
    else
        bpf_map_update_elem(&psid_count, &apsid, &delta, BPF_NOEXIST);
    return 0;
}