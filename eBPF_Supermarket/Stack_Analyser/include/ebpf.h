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

#include "common.h"
#include <linux/version.h>

#define PF_KTHREAD 0x00200000

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
#define BPF_HASH(name, _kt, _vt, _cap)   \
    struct                               \
    {                                    \
        __uint(type, BPF_MAP_TYPE_HASH); \
        __type(key, _kt);                \
        __type(value, _vt);              \
        __uint(max_entries, _cap);       \
    } name SEC(".maps")

/**
 * 用于在eBPF代码中声明通用的maps，其中
 * psid_count_map 存储 <psid, count> 键值对，记录了id（由pid、ksid和usid（内核、用户栈id））及相应的值
 * sid_trace_map 存储 <sid（ksid或usid）, trace> 键值对，记录了栈id（ksid或usid）及相应的栈
 * pid_tgid 存储 <pid, tgid> 键值对，记录pid以及对应的tgid
 * pid_comm 存储 <pid, comm> 键值对，记录pid以及对应的命令名
 * type：指定count值的类型
 */
#define COMMON_MAPS(count_type)                              \
    BPF_HASH(psid_count_map, psid, count_type, MAX_ENTRIES); \
    BPF_STACK_TRACE(sid_trace_map);                          \
    BPF_HASH(tgid_cgroup_map, __u32,                         \
             char[CONTAINER_ID_LEN], MAX_ENTRIES / 100);     \
    BPF_HASH(pid_info_map, u32, task_info, MAX_ENTRIES / 10);

#define COMMON_VALS                           \
    const volatile bool trace_user = false;   \
    const volatile bool trace_kernel = false; \
    const volatile __u64 target_cgroupid = 0; \
    const volatile __u32 target_tgid = 0;     \
    const volatile __u32 self_tgid = 0;       \
    const volatile __u32 freq = 0;            \
    bool __active = false;                    \
    __u64 __last_n = 0;                       \
    __u64 __next_n = 0;

#define CHECK_ACTIVE \
    if (!__active)   \
        return 0;

#define TS bpf_ktime_get_ns()

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
#define CHECK_FREQ(_ts)
#else
/*
 内置函数:
    bool __atomic_compare_exchange_n (
        type *ptr, type *expected, type desired, bool weak,
        int success_memorder, int failure_memorder
    )

 * 内置函数__atomic_compare_exchange_n实现了原子性的比较和交换操作。
 * 该函数用于比较指针ptr所指向位置的内容与expected所指向位置的内容。
 * 如果相等，则进行读-修改-写操作，将desired数据写入ptr；
 * 如果不相等，则进行读操作，将当前ptr的内容写入expected。
 * 参数weak表示使用弱类型compare_exchange（true）
 * 或强类型compare_exchange（false），
 * 其中弱类型可能会失败而强类型永远不会失败。
 * 在许多情况下，目标只提供了强变体并忽略了该参数。
 * 当存在疑虑时，请使用强变体。
 *
 * 如果desired成功写入ptr，则返回true，
 * 并根据success_memorder指定的内存顺序影响内存；
 * 对可用的内存顺序没有限制。
 *
 * 否则，返回false，并根据failure_memorder影响内存；
 * 该内存顺序不能是__ATOMIC_RELEASE或__ATOMIC_ACQ_REL，
 * 并且不能比success_memorder更严格。
 */
#define CHECK_FREQ(_ts)                               \
    if (freq)                                         \
    {                                                 \
        __next_n = (_ts * freq) >> 30;                \
        if (__atomic_compare_exchange_n(              \
                &__next_n, &__last_n, __next_n, true, \
                __ATOMIC_RELAXED, __ATOMIC_RELAXED))  \
            return 0;                                 \
    }
#endif

#define GET_CURR \
    (struct task_struct *)bpf_get_current_task()

// 如果没有设置目标进程，则检查被采集进程是否为内核线程，是则退出采集
#define CHECK_KTHREAD(_task)                                      \
    if (!target_tgid && BPF_CORE_READ(_task, flags) & PF_KTHREAD) \
        return 0;

#define CHECK_TGID(_tgid)                                                              \
    if ((!_tgid) || (_tgid == self_tgid) || (target_tgid > 0 && _tgid != target_tgid)) \
        return 0;

#define GET_KNODE(_task) \
    BPF_CORE_READ(_task, cgroups, dfl_cgrp, kn)

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
#define CHECK_CGID(_knode)                                                      \
    if (target_cgroupid > 0 && BPF_CORE_READ(_knode, id.id) != target_cgroupid) \
        return 0;
#else
#define CHECK_CGID(_knode)                                                   \
    if (target_cgroupid > 0 && BPF_CORE_READ(_knode, id) != target_cgroupid) \
        return 0;
#endif

#define TRY_SAVE_INFO(_task, _pid, _tgid, _knode)                                                  \
    if (!bpf_map_lookup_elem(&pid_info_map, &_pid))                                                \
    {                                                                                              \
        task_info info = {0};                                                                      \
        bpf_core_read_str(info.comm, COMM_LEN, &_task->comm);                                      \
        info.tgid = _tgid;                                                                         \
        bpf_map_update_elem(&pid_info_map, &_pid, &info, BPF_NOEXIST);                             \
        if (!bpf_map_lookup_elem(&tgid_cgroup_map, &(info.tgid)))                                  \
        {                                                                                          \
            char cgroup_name[CONTAINER_ID_LEN] = {0};                                              \
            bpf_probe_read_kernel_str(cgroup_name, CONTAINER_ID_LEN, BPF_CORE_READ(_knode, name)); \
            bpf_map_update_elem(&tgid_cgroup_map, &(info.tgid), &cgroup_name, BPF_NOEXIST);        \
        }                                                                                          \
    }

#define TRACE_AND_GET_COUNT_KEY(_pid, _ctx)                                                                       \
    {                                                                                                             \
        .pid = _pid,                                                                                              \
        .usid = trace_user ? bpf_get_stackid(_ctx, &sid_trace_map, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK) : -1, \
        .ksid = trace_kernel ? bpf_get_stackid(_ctx, &sid_trace_map, BPF_F_FAST_STACK_CMP) : -1,                  \
    }

#endif