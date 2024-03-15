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

#include "sa_ebpf.h"
#include "task.h"

DeclareCommonMaps(u32);
DeclareCommonVar();

int apid = 0;
BPF_HASH(start, u32, u64);                                                  //记录进程运行的起始时间

const char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/finish_task_switch.isra.0")                                     //动态挂载点finish_task_switch.isra.0
int BPF_KPROBE(do_stack, struct task_struct *curr)
{
    // u32 pid = BPF_CORE_READ(curr, pid);
    u32 pid = get_task_ns_pid(curr);                                        //利用帮助函数获取当前进程tsk的pid
    ignoreKthread(curr);
    if ((apid >= 0 && pid == apid) || (apid < 0 && pid && pid != self_pid))
    {
        // record curr block time
        u64 ts = bpf_ktime_get_ns();                                        //ts=当前的时间戳（ns）
        bpf_map_update_elem(&start, &pid, &ts, BPF_NOEXIST);                //如果start表中不存在pid对应的时间，则就创建pid-->ts
    }
    
    // calculate time delta, next ready to run
    struct task_struct *next = (struct task_struct *)bpf_get_current_task();//next指向当前的结构体
    // pid = BPF_CORE_READ(next, pid);
    pid = get_task_ns_pid(next);                                            //利用帮助函数获取next指向的tsk的pid
    u64 *tsp = bpf_map_lookup_elem(&start, &pid);                           //tsp指向start表中的pid的值
    if (!tsp)
        return 0;
    bpf_map_delete_elem(&start, &pid);                                      //存在tsp,则删除pid对应的值
    u32 delta = (bpf_ktime_get_ns() - *tsp) >> 20;                          //delta为当前时间戳 - 原先tsp指向start表中的pid的值.代表运行时间

    if ((delta <= min) || (delta > max))
        return 0;

    // record data
    // u32 tgid = BPF_CORE_READ(next, tgid);
    u32 tgid = get_task_ns_tgid(curr);                                      //利用帮助函数获取当前进程的的tgid
    bpf_map_update_elem(&pid_tgid, &pid, &tgid, BPF_ANY);                   //利用帮助函数更新tgid对应的pid表项
    comm *p = bpf_map_lookup_elem(&pid_comm, &pid);                         //p指向pid_comm中pid对应的表项
    if (!p)
    {
        comm name;
        bpf_probe_read_kernel_str(&name, COMM_LEN, next->comm);             //获取next指向的进程结构体的comm，赋值给comm
        bpf_map_update_elem(&pid_comm, &pid, &name, BPF_NOEXIST);           //如果pid_comm中不存在pid项，则创建
    }
    psid apsid = {
        .pid = pid,
        .usid = u ? USER_STACK : -1,
        .ksid = k ? KERNEL_STACK : -1,
    };

    // record time delta
    u32 *count = bpf_map_lookup_elem(&psid_count, &apsid);                  //count指向psid_count中的apsid对应的值
    if (count)
        (*count) += delta;                                                  //如果count存在，则psid_count中的apsid对应的值+=时间戳
    else
        bpf_map_update_elem(&psid_count, &apsid, &delta, BPF_NOEXIST);      //如果不存在，则将psid_count表中的apsid设置为delta
    return 0;
}