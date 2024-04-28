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
#include <bpf/usdt.bpf.h>

#include "sa_ebpf.h"
#include "bpf_wapper/funclatency.h"
#include "task.h"

COMMON_MAPS(time_tuple);
COMMON_VALS;
BPF_HASH(starts,psid,u64);
const volatile int target_pid = 0;

static int entry(void *ctx)
{
	CHECK_ACTIVE;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task(); // 利用bpf_get_current_task()获得当前的进程tsk
    RET_IF_KERN(curr);

    u32 pid = get_task_ns_pid(curr); // 利用帮助函数获得当前进程的pid
    if ((target_pid >= 0 && pid != target_pid) || !pid || pid == self_pid)
        return 0;

    SAVE_TASK_INFO(pid, curr);

    psid a_psid =GET_COUNT_KEY(pid,ctx);
	u64 nsec;

	nsec = bpf_ktime_get_ns();
	bpf_map_update_elem(&starts, &a_psid, &nsec, BPF_ANY);
}



SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe)
{
	entry(ctx);
	return 0;
}
SEC("tp/sched/dummy_tp")
int tp_entry(void *ctx)
{
    entry(ctx);
    return 0;
}
SEC("usdt")
int usdt_entry(void *ctx)
{
    entry(ctx);
    return 0;
}
static int  exit(void *ctx)
{
	u64 *start;
	u64 nsec = bpf_ktime_get_ns();
	u64 delta;
    
    

	CHECK_ACTIVE;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task(); // 利用bpf_get_current_task()获得当前的进程tsk
    RET_IF_KERN(curr);

    u32 pid = get_task_ns_pid(curr); // 利用帮助函数获得当前进程的pid
    if ((target_pid >= 0 && pid != target_pid) || !pid || pid == self_pid)
        return 0;

    SAVE_TASK_INFO(pid, curr);

    psid b_psid = GET_COUNT_KEY(pid, ctx);
    
	start = bpf_map_lookup_elem(&starts, &b_psid);
	if (!start)
		return 0;

	delta = nsec - *start;

    time_tuple *d = bpf_map_lookup_elem(&psid_count_map, &b_psid); 
    if (!d)
    {
        time_tuple tmp = {.lat = delta,.count=1};
        bpf_map_update_elem(&psid_count_map, &b_psid, &tmp, BPF_NOEXIST);
    }
    else
    {
        d->lat+=delta;
        d->count++;
    }
}



SEC("kretprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe)
{
	exit(ctx);
	return 0;
}
SEC("tp/sched/dummy_tp")
int tp_exit(void *ctx)
{
    exit(ctx);
    return 0;
}
SEC("usdt")
int usdt_exit(void *ctx)
{
    exit(ctx);
    return 0;
}
const char LICENSE[] SEC("license") = "GPL";