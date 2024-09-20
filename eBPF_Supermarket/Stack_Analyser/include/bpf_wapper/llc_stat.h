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
// ebpf程序的包装类的模板，声明接口和一些自定义方法，以及辅助结构

#ifndef _SA_LLC_STAT_H__
#define _SA_LLC_STAT_H__

// ========== C code part ==========

#include <asm/types.h>

typedef struct
{
    __u64 miss;
    __u64 ref;
} llc_stat;

// ========== C code end ==========

#ifdef __cplusplus
// ========== C++ code part ==========
#include "bpf_wapper/eBPFStackCollector.h"
#include "llc_stat.skel.h"

class LlcStatStackCollector : public StackCollector
{
private:
    DECL_SKEL(llc_stat);
    int *mpefds = NULL;
    int *rpefds = NULL;
    int num_cpus = 0;
    struct bpf_link **mlinks = NULL;
    struct bpf_link **rlinks = NULL;

protected:
    virtual uint64_t *count_values(void *);

public:
    LlcStatStackCollector();
    virtual int ready(void);
    virtual void finish(void);
    virtual void activate(bool tf);
    virtual const char *getName(void);
    void setScale(uint64_t period);
};
// ========== C++ code end ==========
#endif

#endif