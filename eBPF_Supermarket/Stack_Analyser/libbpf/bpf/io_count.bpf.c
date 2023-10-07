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

BPF_HASH(psid_count, psid, u64);
BPF_STACK_TRACE(stack_trace);
BPF_HASH(pid_tgid, u32, u32);
BPF_HASH(pid_comm, u32, comm);

const char LICENSE[] SEC("license") = "GPL";

int apid;
bool u, k, cot;
__u64 min, max;

static int do_stack(struct trace_event_raw_sys_enter *ctx)
{
    u64 td = bpf_get_current_pid_tgid();
    u32 pid = td >> 32;

    if ((apid >= 0 && pid != apid) || !pid)
        return 0;

    u64 len = (u64)BPF_CORE_READ(ctx, args[3]);
    if (len < min || len > max)
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

    // record time delta
    u64 *count = bpf_map_lookup_elem(&psid_count, &apsid);
    if (cot)
    {
        if (count)
            (*count)++;
        else
        {
            u64 one = 1;
            bpf_map_update_elem(&psid_count, &apsid, &one, BPF_NOEXIST);
        }
    }
    else
    {
        if (count)
            (*count) += len;
        else
            bpf_map_update_elem(&psid_count, &apsid, &len, BPF_NOEXIST);
    }
    return 0;
}

#define io_sec_tp(name)                         \
    SEC("tracepoint/syscalls/sys_enter_" #name) \
    int prog_t_##name(struct trace_event_raw_sys_enter *ctx) { return do_stack(ctx); }

// tracepoint:syscalls:sys_exit_select
// tracepoint:syscalls:sys_enter_poll
// tracepoint:syscalls:sys_enter_epoll_wait

io_sec_tp(write);
io_sec_tp(read);
io_sec_tp(recvfrom);
io_sec_tp(sendto);
