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

BPF_HASH(pid_size, u32, u64);
BPF_HASH(psid_util, psid, tuple);

const char LICENSE[] SEC("license") = "GPL";

int apid;
char u, k;
__u64 min, max;

SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read_enter) { 
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
    u64 *expc = bpf_map_lookup_elem(&pid_size, &pid);
    if(!expc) return 0;
    tuple *d = bpf_map_lookup_elem(&psid_util, &apsid);
    if(!d) {
        tuple a = {.expect = *expc, .truth = len};
        bpf_map_update_elem(&psid_util, &apsid, &a, BPF_ANY);
    } else {
        d->expect += *expc;
        d->truth += len;
    }
    bpf_map_delete_elem(&pid_size, &pid);

    return 0;
}

SEC("uprobe/read")
int BPF_KPROBE(read_enter)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if ((apid >= 0 && pid == apid) || (apid < 0 && !pid))
    {
        u64 len = PT_REGS_PARM3(ctx);
        bpf_map_update_elem(&pid_size, &pid, &len, BPF_NOEXIST);
    }
    return 0;
}