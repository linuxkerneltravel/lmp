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
// author: GaoYiXiang
//
// ebpf程序的包装类的模板，声明接口和一些自定义方法，以及辅助结构

#ifndef _SA_BIO_H__
#define _SA_BIO_H__
#include <asm/types.h>
#include <sa_common.h>
// ========== C code part ==========
struct internal_rqinfo
{
    __u64 start_ts;
    struct rqinfo rqinfo;
};
// ========== C code end ========== 

#ifdef __cplusplus
// ========== C++ code part ==========
#include "bio.skel.h"
#include "bpf_wapper/eBPFStackCollector.h"

class BioStackCollector : public StackCollector
{
private:
    declareEBPF(bio);

protected:
    virtual double count_value(void *);

public:
    BioStackCollector();
    virtual int load(void);
    virtual int attach(void);
    virtual void detach(void);
    virtual void unload(void);
};
// ========== C++ code end ==========
#endif

#endif