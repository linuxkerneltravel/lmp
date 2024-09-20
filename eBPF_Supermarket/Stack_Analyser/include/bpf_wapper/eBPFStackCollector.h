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
// 包装用于采集调用栈数据的eBPF程序，声明接口、通用成员和一些辅助结构

#ifndef _SA_STACK_COLLECTOR_H__
#define _SA_STACK_COLLECTOR_H__

#include <stdint.h>
#include <unistd.h>
#include <vector>
#include <string>
#include "user.h"

struct Scale
{
    std::string Type;
    uint64_t Period;
    std::string Unit;
};

/// @brief count类，主要是为了重载比较运算，便于自动排序
struct CountItem
{
    psid k;
    uint64_t *v;
    CountItem(psid k, uint64_t *v) : k(k), v(v){};

    /// @brief count对象的大小取决于val的大小
    /// @param b 要比较的对象
    /// @return 小于b则为真，否则为假
    friend bool operator<(const CountItem a, const CountItem b);
};

class StackCollector
{
protected:
    int self_tgid = -1;
    struct bpf_object *obj = NULL;

    // 默认显示计数的变化情况，即每次输出数据后清除计数
    bool showDelta = true;
    int scale_num;

public:
    Scale *scales;

    uint32_t top = 10;
    uint32_t freq = 49;
    uint64_t cgroup = 0;
    uint32_t tgid = 0;
    int err = 0; // 用于保存错误代码

    bool ustack = false; // 是否跟踪用户栈
    bool kstack = false; // 是否跟踪内核栈

protected:
    std::vector<CountItem> *sortedCountList(void);

    /// @brief 将缓冲区的数据解析为特定值
    /// @param  无
    /// @return 解析出的值
    virtual uint64_t *count_values(void *data) = 0;

public:
    StackCollector();
    operator std::string();

    virtual int ready(void) = 0;
    virtual void finish(void) = 0;

    /// @brief 激活eBPF程序
    /// @param  无
    virtual void activate(bool) = 0;

    virtual const char *getName(void) = 0;

// 声明eBPF骨架
#define DECL_SKEL(func) struct func##_bpf *skel = NULL;

/// @brief 加载、初始化参数并打开指定类型的ebpf程序
/// @param ... 一些ebpf程序全局变量初始化语句
/// @note 失败会使上层函数返回-1
#define EBPF_LOAD_OPEN_INIT(...)                           \
    {                                                      \
        skel = skel->open(NULL);                           \
        CHECK_ERR_RN1(!skel, "Fail to open BPF skeleton"); \
        __VA_ARGS__;                                       \
        skel->rodata->trace_user = ustack;                 \
        skel->rodata->trace_kernel = kstack;               \
        skel->rodata->self_tgid = self_tgid;               \
        skel->rodata->target_tgid = tgid;                  \
        skel->rodata->target_cgroupid = cgroup;            \
        skel->rodata->freq = freq;                         \
        err = skel->load(skel);                            \
        CHECK_ERR_RN1(err, "Fail to load BPF skeleton");   \
        obj = skel->obj;                                   \
    }

#define ATTACH_PROTO                                         \
    {                                                        \
        err = skel->attach(skel);                            \
        CHECK_ERR_RN1(err, "Failed to attach BPF skeleton"); \
    }

#define DETACH_PROTO            \
    {                           \
        if (skel)               \
        {                       \
            skel->detach(skel); \
        }                       \
    }

#define UNLOAD_PROTO             \
    {                            \
        if (skel)                \
        {                        \
            skel->destroy(skel); \
        }                        \
        skel = NULL;             \
    }
};

#define ACTIVE_SET(_b) \
    skel->bss->__active = _b;

#endif