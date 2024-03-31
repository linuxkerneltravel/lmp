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
// 用于eBPF程序的宏

#ifndef STACK_ANALYZER_EBPF
#define STACK_ANALYZER_EBPF

#include "sa_common.h"

#define PF_KTHREAD 0x00200000
#define RET_IF_KERN(task)                       \
    do                                          \
    {                                           \
        int flags = BPF_CORE_READ(task, flags); \
        if (flags & PF_KTHREAD)                 \
            return 0;                           \
    } while (false)

/// @brief 创建一个指定名字的ebpf调用栈表
/// @param 新栈表的名字
#define BPF_STACK_TRACE(name)                           \
    struct                                              \
    {                                                   \
        __uint(type, BPF_MAP_TYPE_STACK_TRACE);         \
        __uint(key_size, sizeof(__u32));                \
        __uint(value_size, MAX_STACKS * sizeof(__u64)); \
        __uint(max_entries, MAX_ENTRIES);               \
    } name SEC(".maps")

/// @brief 创建一个指定名字和键值类型的ebpf散列表
/// @param name 新散列表的名字
/// @param type1 键的类型
/// @param type2 值的类型
#define BPF_HASH(name, type1, type2)       \
    struct                                 \
    {                                      \
        __uint(type, BPF_MAP_TYPE_HASH);   \
        __uint(key_size, sizeof(type1));   \
        __uint(value_size, sizeof(type2)); \
        __uint(max_entries, MAX_ENTRIES);  \
    } name SEC(".maps")

/**
 * 用于在eBPF代码中声明通用的maps，其中
 * psid_count_map 存储 <psid, count> 键值对，记录了id（由pid、ksid和usid（内核、用户栈id））及相应的值
 * sid_trace_map 存储 <sid（ksid或usid）, trace> 键值对，记录了栈id（ksid或usid）及相应的栈
 * pid_tgid 存储 <pid, tgid> 键值对，记录pid以及对应的tgid
 * pid_comm 存储 <pid, comm> 键值对，记录pid以及对应的命令名
 * type：指定count值的类型
 */
#define COMMON_MAPS(count_type)                 \
    BPF_HASH(psid_count_map, psid, count_type); \
    BPF_STACK_TRACE(sid_trace_map);             \
    BPF_HASH(pid_info_map, u32, task_info);

#define COMMON_VALS                           \
    const volatile bool trace_user = false;   \
    const volatile bool trace_kernel = false; \
    const volatile __u64 min = 0;             \
    const volatile __u64 max = 0;             \
    const volatile int self_pid = 0;

#define SAVE_TASK_INFO(_pid, _task)                                    \
    if (!bpf_map_lookup_elem(&pid_info_map, &_pid))                    \
    {                                                                  \
        task_info info;                                                \
        info.pid = get_task_ns_pid(_task);                             \
        bpf_get_current_comm(info.comm, COMM_LEN);                     \
        info.tgid = get_task_ns_tgid(_task);                           \
        fill_container_id(_task, info.cid);                            \
        bpf_map_update_elem(&pid_info_map, &_pid, &info, BPF_NOEXIST); \
    }

#define GET_COUNT_KEY(_pid, _ctx)                                                                                 \
    ((psid){                                                                                                      \
        .pid = _pid,                                                                                              \
        .usid = trace_user ? bpf_get_stackid(_ctx, &sid_trace_map, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK) : -1, \
        .ksid = trace_kernel ? bpf_get_stackid(_ctx, &sid_trace_map, BPF_F_FAST_STACK_CMP) : -1,                  \
    })

#endif