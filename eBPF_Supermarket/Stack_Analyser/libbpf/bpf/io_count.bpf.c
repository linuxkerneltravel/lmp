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
// 内核态bpf的io-cpu模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "stack_analyzer.h"

#define MINBLOCK_US 1ULL
#define MAXBLOCK_US 99999999ULL

BPF_HASH(psid_count, psid, u32);
BPF_STACK_TRACE(stack_trace);
BPF_HASH(pid_tgid, u32, u32);
BPF_HASH(pid_comm, u32, comm);

const char LICENSE[] SEC("license") = "GPL";

int apid;
char u, k;

int do_stack(struct pt_regs *ctx)
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

    u32 len = PT_REGS_PARM3(ctx);

    // record time delta
    u32 *count = bpf_map_lookup_elem(&psid_count, &apsid);
    if (count)
        (*count) += len;
    else
        bpf_map_update_elem(&psid_count, &apsid, &len, BPF_NOEXIST);
    return 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(write_enter) { return do_stack(ctx); }

SEC("kprobe/vfs_read")
int BPF_KPROBE(read_enter) { return do_stack(ctx); }