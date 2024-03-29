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
// 内核态bpf的on-cpu模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "sa_ebpf.h"
#include "task.h"

const char LICENSE[] SEC("license") = "GPL";

COMMON_MAPS(u32);
COMMON_VALS;
unsigned long *const volatile load_a = NULL;

SEC("perf_event") // 挂载点为perf_event
int do_stack(void *ctx)
{
    if (load_a != NULL)
    {
        unsigned long load;
        bpf_core_read(&load, sizeof(unsigned long), load_a); // load为文件中读出的地址，则该地址开始读取unsigned long大小字节的数据保存到load
        load >>= 11;                                         // load右移11
        bpf_printk("%lu %lu", load, min);                    // 输出load 以及min
        if (load < min || load > max)
            return 0;
    }
    // record data
    struct task_struct *curr = (void *)bpf_get_current_task(); // curr指向当前进程的tsk
    RET_IF_KERN(curr);                                       // 忽略内核线程
    u32 pid = BPF_CORE_READ(curr, pid);                        // pid保存当前进程的pid，是cgroup pid 对应的level 0 pid
    if (!pid || pid == self_pid)
        return 0;
    SAVE_TASK_INFO(pid, curr);
    psid apsid = GET_COUNT_KEY(pid, ctx);

    // add cosunt
    u32 *count = bpf_map_lookup_elem(&psid_count_map, &apsid); // count指向psid_count对应的apsid的值
    if (count)
        (*count)++; // count不为空，则psid_count对应的apsid的值+1
    else
    {
        u32 orig = 1;
        bpf_map_update_elem(&psid_count_map, &apsid, &orig, BPF_ANY); // 否则psid_count对应的apsid的值=1
    }
    return 0;
}