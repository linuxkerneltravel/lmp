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
// 内核态bpf的off-cpu模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "sa_ebpf.h"
#include "task.h"

COMMON_MAPS(u32);
COMMON_VALS;

const volatile int apid = 0;
BPF_HASH(start, u32, u64);                                                  //记录进程运行的起始时间

const char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/finish_task_switch")                                     //动态挂载点finish_task_switch.isra.0
int BPF_KPROBE(do_stack, struct task_struct *curr)
{
    u32 pid = BPF_CORE_READ(curr, pid);                                        //利用帮助函数获取当前进程tsk的pid
    RET_IF_KERN(curr);
    if ((apid >= 0 && pid == apid) || (apid < 0 && pid && pid != self_pid))
    {
        // record curr block time
        u64 ts = bpf_ktime_get_ns();                                        //ts=当前的时间戳（ns）
        bpf_map_update_elem(&start, &pid, &ts, BPF_NOEXIST);                //如果start表中不存在pid对应的时间，则就创建pid-->ts
    }
    
    // calculate time delta, next ready to run
    struct task_struct *next = (struct task_struct *)bpf_get_current_task();//next指向当前的结构体
    pid = BPF_CORE_READ(next, pid);                                            //利用帮助函数获取next指向的tsk的pid
    u64 *tsp = bpf_map_lookup_elem(&start, &pid);                           //tsp指向start表中的pid的值
    if (!tsp)
        return 0;
    bpf_map_delete_elem(&start, &pid);                                      //存在tsp,则删除pid对应的值
    u32 delta = (bpf_ktime_get_ns() - *tsp) >> 20;                          //delta为当前时间戳 - 原先tsp指向start表中的pid的值.代表运行时间

    if ((delta <= min) || (delta > max))
        return 0;

    // record data
    SAVE_TASK_INFO(pid, next);
    psid apsid = GET_COUNT_KEY(pid, ctx);

    // record time delta
    u32 *count = bpf_map_lookup_elem(&psid_count_map, &apsid);                  //count指向psid_count中的apsid对应的值
    if (count)
        (*count) += delta;                                                  //如果count存在，则psid_count中的apsid对应的值+=时间戳
    else
        bpf_map_update_elem(&psid_count_map, &apsid, &delta, BPF_NOEXIST);      //如果不存在，则将psid_count表中的apsid设置为delta
    return 0;
}