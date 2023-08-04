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

#define MAX_STACKS 32
#define MAX_ENTRIES 102400
#define COMM_LEN 16

#include <asm/types.h>
#include <linux/version.h>

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
            0,                                                   \
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
            0,                                                   \
            &uprobe_opts);                                       \
    } while (false)
#endif

#define __CHECK_PROGRAM(skel, prog_name)                                                      \
    do                                                                                        \
    {                                                                                         \
        if (!skel->links.prog_name)                                                           \
        {                                                                                     \
            fprintf(stderr, "[%s] no program attached for" #prog_name "\n", strerror(errno)); \
            return -errno;                                                                    \
        }                                                                                     \
    } while (false)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
    do                                                                  \
    {                                                                   \
        __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe);        \
        __CHECK_PROGRAM(skel, prog_name);                               \
    } while (false)

#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

#define CHECK_ERR(cond, info)                               \
    if (cond)                                               \
    {                                                       \
        fprintf(stderr, "[%s]" info "\n", strerror(errno));                                   \
        return -1;                                          \
    }

#define LOAD_SKEL_CHECKED(type, var) \
    bpf_open_load(type, var);        \
    skel = var;                      \
    CHECK_ERR(!skel, "Fail to open and load BPF skeleton")

#define LOAD_CHECKED(type, var)        \
    var = type##_bpf__open_and_load(); \
    CHECK_ERR(!var, "Fail to open and load BPF skeleton")

#define BPF_STACK_TRACE(name)                           \
    struct                                              \
    {                                                   \
        __uint(type, BPF_MAP_TYPE_STACK_TRACE);         \
        __uint(key_size, sizeof(__u32));                \
        __uint(value_size, MAX_STACKS * sizeof(__u64)); \
        __uint(max_entries, MAX_ENTRIES);               \
    } name SEC(".maps")

#define BPF_HASH(name, type1, type2)       \
    struct                                 \
    {                                      \
        __uint(type, BPF_MAP_TYPE_HASH);   \
        __uint(key_size, sizeof(type1));   \
        __uint(value_size, sizeof(type2)); \
        __uint(max_entries, MAX_ENTRIES);  \
    } name SEC(".maps")

#define BPF(type, name) (struct type##_bpf *)name
#define bpf_open_load(type, name) struct type##_bpf *name = type##_bpf__open_and_load()
#define bpf_destroy(type, name) type##_bpf__destroy(BPF(type, name))
#define bpf_attach(type, name) type##_bpf__attach(BPF(type, name))

#define KERNEL_STACK bpf_get_stackid(ctx, &stack_trace, BPF_F_FAST_STACK_CMP)
#define USER_STACK bpf_get_stackid(ctx, &stack_trace, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

#define TRAVERSE_MAP(mapfd, prev, key, val, process)  \
    memset(&prev, 0, sizeof(prev));                   \
    while (!bpf_map_get_next_key(mapfd, &prev, &key)) \
    {                                                 \
        bpf_map_lookup_elem(mapfd, &key, &val);       \
        process;                                      \
        prev = key;                                   \
    }

typedef struct
{
    __u32 pid;
    __s32 ksid, usid;
} psid; // counts key

typedef struct
{
    char str[COMM_LEN];
} comm; // pid name

typedef struct
{
    __u64 addr;
    __u32 pid, o;
} piddr; // mem info key

typedef struct
{
    __u64 size;
    __u32 usid, o;
} mem_info; // mem info with stack

typedef enum
{
    MOD_ON_CPU,
    MOD_OFF_CPU,
    MOD_MEM,
} MOD; // simpling mod

#endif