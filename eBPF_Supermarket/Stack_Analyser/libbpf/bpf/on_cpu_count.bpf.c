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

#include "sa_ebpf.h"
#include "task.h"

const char LICENSE[] SEC("license") = "GPL";

DeclareCommonMaps(u32);
DeclareCommonVar();
unsigned long *load_a = NULL;

SEC("perf_event")                                                               //挂载点为perf_event
int do_stack(void *ctx)
{
    unsigned long load;
    bpf_core_read(&load, sizeof(unsigned long), load_a);                        //load为文件中读出的地址，则该地址开始读取unsigned long大小字节的数据保存到load
    load >>= 11;                                                                //load右移11
    bpf_printk("%lu %lu", load, min);                                           //输出load 以及min
    if (load < min || load > max)
        return 0;
    // record data
    struct task_struct *curr = (void *)bpf_get_current_task();                  //curr指向当前进程的tsk
    ignoreKthread(curr);                                                        // 忽略内核线程
    u32 pid = get_task_ns_pid(curr);                                      //pid保存当前进程的pid，是cgroup pid 对应的level 0 pid
    if (!pid || pid == self_pid)
        return 0;
    u32 tgid = get_task_ns_tgid(curr);                                  //tgid保存当前进程的tgid
    bpf_map_update_elem(&pid_tgid, &pid, &tgid, BPF_ANY);                       //更新pid_tgid表中的pid表项
    comm *p = bpf_map_lookup_elem(&pid_comm, &pid);                             //p指向pid_comm中的Pid对应的值
    if (!p)
    {
        comm name;
        bpf_probe_read_kernel_str(&name, COMM_LEN, curr->comm);                 //name中保存的是当前进程tsk的进程名
        bpf_map_update_elem(&pid_comm, &pid, &name, BPF_NOEXIST);               //更新pid_comm中的进程号对应的进程名
    }
    psid apsid = {
        .pid = pid,
        .usid = u ? USER_STACK : -1,
        .ksid = k ? KERNEL_STACK : -1,
    };

    // add cosunt
    u32 *count = bpf_map_lookup_elem(&psid_count, &apsid);                          //count指向psid_count对应的apsid的值
    if (count)
        (*count)++;                                                                  //count不为空，则psid_count对应的apsid的值+1
    else
    {
        u32 orig = 1;
        bpf_map_update_elem(&psid_count, &apsid, &orig, BPF_ANY);                   //否则psid_count对应的apsid的值=1
    }
    return 0;
}