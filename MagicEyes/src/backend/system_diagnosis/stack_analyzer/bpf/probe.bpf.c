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
// author: GaoYixiang
//
// 内核态eBPF的通用的调用栈计数代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "sa_ebpf.h"
#include "task.h"

DeclareCommonMaps(u32);
DeclareCommonVar();

// 传进来的参数
int apid = 0;

const char LICENSE[] SEC("license") = "GPL";

static int handle_func(void *ctx)
{
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task(); // 利用bpf_get_current_task()获得当前的进程tsk
    ignoreKthread(curr);

    u32 pid = get_task_ns_pid(curr); // 利用帮助函数获得当前进程的pid
    if ((apid >= 0 && pid != apid) || !pid || pid == self_pid)
        return 0;

    u32 tgid = get_task_ns_tgid(curr);                    // 利用帮助函数获取进程的tgid
    bpf_map_update_elem(&pid_tgid, &pid, &tgid, BPF_ANY); // 将pid_tgid表中的pid选项更新为tgid,若没有该表项，则创建

    if (!bpf_map_lookup_elem(&pid_comm, &pid))
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

    u32 *cnt = bpf_map_lookup_elem(&psid_count, &apsid);
    if (!cnt)
    {
        u32 ONE = 1;
        bpf_map_update_elem(&psid_count, &apsid, &ONE, BPF_NOEXIST);
    }
    else
    {
        (*cnt)++;
    }

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