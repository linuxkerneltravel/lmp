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

#ifndef _TEMPLATE_H__
#define _TEMPLATE_H__

// ========== C code part ==========

// ========== C code end ==========

#ifdef __cplusplus
// ========== C++ code part ==========
#include "template.skel.h"
#include "bpf_wapper/eBPFStackCollector.h"

class TemplateClass : public StackCollector
{
private:
    DECL_SKEL(template);

protected:
    virtual uint64_t *count_values(void *);

public:
    TemplateClass();
    virtual int ready(void);
    virtual void finish(void);
    virtual void activate(bool tf);
    virtual const char *getName(void);
};
// ========== C++ code end ==========
#endif

#endif