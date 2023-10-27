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
// 通用数据结构和宏

#ifndef STACK_ANALYZER
#define STACK_ANALYZER

#define MAX_STACKS 32      // 栈最大深度
#define MAX_ENTRIES 102400 // map容量
#define COMM_LEN 16        // 进程名最大长度

#include <asm/types.h>
#include <linux/version.h>

extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

/// @brief 向指定用户函数附加一个ebpf处理函数
/// @param skel ebpf程序骨架
/// @param sym_name 用户态函数名
/// @param prog_name ebpf处理函数
/// @param is_retprobe 布尔类型，是否附加到符号返回处
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe)  \
    do                                                           \
    {                                                            \
        DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,        \
                            .retprobe = is_retprobe);            \
        skel->links.prog_name = bpf_program__attach_uprobe_opts( \
            skel->progs.prog_name,                               \
            pid,                                                 \
            object,                                              \
            1,                                                   \
            &uprobe_opts);                                       \
    } while (false)
#else
#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe)  \
    do                                                           \
    {                                                            \
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,                \
                    .retprobe = is_retprobe,                     \
                    .func_name = #sym_name);                     \
        skel->links.prog_name = bpf_program__attach_uprobe_opts( \
            skel->progs.prog_name,                               \
            pid,                                                 \
            object,                                              \
            1,                                                   \
            &uprobe_opts);                                       \
    } while (false)
#endif

/// @brief 检查处理函数是否已经被附加到函数上
/// @param skel ebpf程序骨架
/// @param prog_name ebpf处理函数
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define __CHECK_PROGRAM(skel, prog_name)                                                      \
    do                                                                                        \
    {                                                                                         \
        if (!skel->links.prog_name)                                                           \
        {                                                                                     \
            fprintf(stderr, "[%s] no program attached for" #prog_name "\n", strerror(errno)); \
            return -errno;                                                                    \
        }                                                                                     \
    } while (false)

/// @brief 向指定用户函数附加一个处理函数并检查是否连接成功
/// @param skel ebpf程序骨架
/// @param sym_name 要连接的用户函数
/// @param prog_name ebpf处理函数
/// @param is_retprobe 布尔类型，是否附加到函数返回处
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
    do                                                                  \
    {                                                                   \
        __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe);        \
        __CHECK_PROGRAM(skel, prog_name);                               \
    } while (false)

/// @brief 向指定用户态函数入口处附加一个处理函数
/// @param skel ebpf程序骨架
/// @param sym_name 要附加的用户态函数名
/// @param prog_name ebpf处理函数
#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)

/// @brief 向指定用户态函数返回处附加一个处理函数
/// @param skel ebpf程序骨架
/// @param sym_name 用户态函数名
/// @param prog_name ebpf处理函数
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

/// @brief 向指定用户态函数入口处附加一个处理函数并检查是否连接成功
/// @param skel ebpf程序骨架
/// @param sym_name 要跟踪的用户态函数名
/// @param prog_name ebpf处理函数
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)

/// @brief 向指定用户态函数返回处附加一个处理函数并检查是否连接成功
/// @param skel ebpf程序骨架
/// @param sym_name 要附加的用户态函数名
/// @param prog_name ebpf处理函数
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

/// @brief 检查错误，若错误成立则打印带原因的错误信息并使上层函数返回-1
/// @param cond 被检查的条件表达式
/// @param info 要打印的错误信息
#define CHECK_ERR(cond, ...)                         \
    if (cond)                                        \
    {                                                \
        fprintf(stderr, __VA_ARGS__);                \
        fprintf(stderr, " [%s]\n", strerror(errno)); \
        return -1;                                   \
    }

/// @brief 检查错误，若错误成立则打印带原因的错误信息并退出
/// @param cond 被检查的条件表达式
/// @param info 要打印的错误信息
#define CHECK_ERR_EXIT(cond, ...)                    \
    if (cond)                                        \
    {                                                \
        fprintf(stderr, __VA_ARGS__);                \
        fprintf(stderr, " [%s]\n", strerror(errno)); \
        exit(EXIT_FAILURE);                          \
    }

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

/// @brief 将指定地址转变为指定类型的ebpf骨架指针
/// @param type ebpf骨架类型
/// @param name 指针
#define BPF(type, name) (struct type##_bpf *)name
#define bpf_open_load(type, name) struct type##_bpf *name = type##_bpf__open_and_load()
#define bpf_destroy(type, name) type##_bpf__destroy(BPF(type, name))
#define bpf_attach(type, name) type##_bpf__attach(BPF(type, name))

/// @brief 当前进程上下文内核态调用栈id
#define KERNEL_STACK bpf_get_stackid(ctx, &stack_trace, BPF_F_FAST_STACK_CMP)

/// @brief 当前进程上下文用户态调用栈id
#define USER_STACK bpf_get_stackid(ctx, &stack_trace, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

/// @brief 遍历ebpf表值的循环头部
/// @param mapfd 要遍历的ebpf表的描述符
/// @param ktype ebpf表的键类型
/// @param val 保存值的变量
#define TRAVERSE_MAP_HEAD(mapfd, ktype, val)                                           \
    for (ktype prev = {0}, key; !bpf_map_get_next_key(mapfd, &prev, &key); prev = key) \
    {                                                                                  \
        bpf_map_lookup_elem(mapfd, &key, &val);

/// @brief 遍历ebpf表值的循环尾部
#define TRAVERSE_MAP_TAIL \
    }

/// @brief 栈计数的键，可以唯一标识一个用户内核栈
typedef struct
{
    __u32 pid;
    __s32 ksid, usid;
} psid;

/// @brief 进程名
typedef struct
{
    char str[COMM_LEN];
} comm;

/// @brief 内存信息的键，唯一标识一块被分配的内存
/// @note o为可初始化的填充对齐成员，贴合bpf verifier要求
typedef struct
{
    void *addr;
    __u32 pid, o;
} piddr;

/// @brief 内存分配信息，可溯源的一次内存分配
/// @note o为可初始化的填充对齐成员，贴合bpf verifier要求
typedef struct
{
    __u64 size;
    __u32 usid, o;
} mem_info;

/// @brief 栈处理工具当前支持的采集模式
typedef enum
{
    MOD_ON_CPU,  // on—cpu模式
    MOD_OFF_CPU, // off-cpu模式
    MOD_MEM,     // 内存模式
    MOD_IO,      // io模式
    MOD_RA,      // 预读取分析模式
} MOD;

typedef enum
{
    NO_OUTPUT,
    LIST_OUTPUT,
    FLAME_OUTPUT
} display_t;

typedef struct
{
    __u64 truth;
    __u64 expect;
} tuple;

#endif