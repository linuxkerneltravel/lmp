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
// mem ebpf程序的包装类，声明接口和一些自定义方法

#ifndef _SA_MEMORY_H__
#define _SA_MEMORY_H__

#include <asm/types.h>
/// @brief 内存信息的键，唯一标识一块被分配的内存
/// @note o为可初始化的填充对齐成员，贴合bpf verifier要求
typedef struct
{
    __u64 addr;
    __u32 pid;
    __u32 _pad;
} piddr;

/// @brief 内存分配信息，可溯源的一次内存分配
/// @note o为可初始化的填充对齐成员，贴合bpf verifier要求
typedef struct
{
    __u64 size;
    __s32 usid;
    __s32 ksid;
} mem_info;

union combined_alloc_info
{
    struct
    {
        __u64 total_size : 40;
        __u64 number_of_allocs : 24;
    };
    __u64 bits;
};

#ifdef __cplusplus
#include "bpf_wapper/eBPFStackCollector.h"
#include "memleak.skel.h"

class MemleakStackCollector : public StackCollector
{
private:
    struct memleak_bpf *skel = __null;

public:
    char *object = (char *)"libc.so.6";
    bool percpu = false;
    bool wa_missing_free = false;

protected:
    virtual uint64_t *count_values(void *d);
    int attach_uprobes(struct memleak_bpf *skel);

public:
    MemleakStackCollector();

    virtual int ready(void);
    virtual void finish(void);
    virtual void activate(bool tf);
    virtual const char *getName(void);

/// @brief 向指定用户函数附加一个ebpf处理函数
/// @param skel ebpf程序骨架
/// @param sym_name 用户态函数名字面量，不加双引号
/// @param prog_name ebpf处理函数，skel->progs中的成员名
/// @param is_retprobe 布尔类型，是否附加到符号返回处
#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe) \
    do                                                          \
    {                                                           \
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,               \
                    .retprobe = is_retprobe,                    \
                    .func_name = #sym_name);                    \
        skel->links.prog_name =                                 \
            bpf_program__attach_uprobe_opts(                    \
                skel->progs.prog_name,                          \
                tgid,                                           \
                object,                                         \
                0,                                              \
                &uprobe_opts);                                  \
    } while (false)

/// @brief 向指定用户函数附加一个处理函数并检查是否连接成功
/// @param skel ebpf程序骨架
/// @param sym_name 要连接的用户函数
/// @param prog_name ebpf处理函数
/// @param is_retprobe 布尔类型，是否附加到函数返回处
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe)               \
    do                                                                                \
    {                                                                                 \
        __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe);                      \
        CHECK_ERR_RN1(!skel->links.prog_name, "no program attached for " #prog_name "\n") \
    } while (false)

#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)
};
#endif

#endif
