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
// ebpf程序包装类的模板，实现接口和一些自定义方法

#include "bpf_wapper/template.h"

// ========== implement virtual func ==========

uint64_t *TemplateClass::count_values(void *data)
{
    return new uint64_t[scale_num]{
        *(uint32_t *)data,
    };
};

int TemplateClass::ready(void)
{
    return 0;
}

void TemplateClass::finish(void) {};

void TemplateClass::activate(bool tf)
{
    ACTIVE_SET(tf);
}

const char *TemplateClass::getName(void)
{
    return "TemplateClass";
}

// ========== other implementations ==========

TemplateClass::TemplateClass(){};