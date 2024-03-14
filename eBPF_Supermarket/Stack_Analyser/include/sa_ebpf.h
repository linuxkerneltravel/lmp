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
// 用于eBPF程序的宏

#ifndef STACK_ANALYZER_EBPF
#define STACK_ANALYZER_EBPF

#include "sa_common.h"

#define PF_KTHREAD 0x00200000
#define ignoreKthread(task) \
    do { \
        int flags = BPF_CORE_READ(task, flags); \
        if(flags & PF_KTHREAD) \
            return 0; \
    } while(false)


/// @brief 创建一个指定名字的ebpf调用栈表
/// @param 新栈表的名字
#define BPF_STACK_TRACE(name)                           \
    struct {                                            \
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
    struct {                               \
        __uint(type, BPF_MAP_TYPE_HASH);   \
        __uint(key_size, sizeof(type1));   \
        __uint(value_size, sizeof(type2)); \
        __uint(max_entries, MAX_ENTRIES);  \
    } name SEC(".maps")

/// @brief 当前进程上下文内核态调用栈id
#define KERNEL_STACK bpf_get_stackid(ctx, &stack_trace, BPF_F_FAST_STACK_CMP)

/// @brief 当前进程上下文用户态调用栈id
#define USER_STACK bpf_get_stackid(ctx, &stack_trace, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

/**
 * 用于在eBPF代码中声明通用的maps，其中
 * psid_count 存储 <psid, count> 键值对，记录了id（由pid、ksid和usid（内核、用户栈id））及相应的值
 * stack_trace 存储 <sid（ksid或usid）, trace> 键值对，记录了栈id（ksid或usid）及相应的栈
 * pid_tgid 存储 <pid, tgid> 键值对，记录pid以及对应的tgid
 * pid_comm 存储 <pid, comm> 键值对，记录pid以及对应的命令名
 * type：指定count值的类型
 */
#define DeclareCommonMaps(type)            \
    BPF_HASH(psid_count, psid, type); \
    BPF_STACK_TRACE(stack_trace);     \
    BPF_HASH(pid_tgid, u32, u32);     \
    BPF_HASH(pid_comm, u32, comm);

#define DeclareCommonVar()       \
    bool u = false, k = false;  \
    __u64 min = 0, max = 0;     \
    int self_pid = 0;

#endif