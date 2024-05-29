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
// off cpu ebpf程序的包装类，实现接口和一些自定义方法

#include "bpf_wapper/off_cpu.h"
#include "dt_symbol.h"

OffCPUStackCollector::OffCPUStackCollector()
{
    scale_num = 1;
    scales = new Scale[scale_num]{
        {"OffCPUTime", 1 << 20, "nanoseconds"},
    };
};

uint64_t *OffCPUStackCollector::count_values(void *data)
{
    return new uint64_t[scale_num]{
        *(uint32_t *)data,
    };
};

int OffCPUStackCollector::ready(void)
{
    EBPF_LOAD_OPEN_INIT();
    symbol sym;
    sym.name = "finish_task_switch";
    if (!g_symbol_parser.complete_kernel_symbol(sym))
    {
        return -1;
    }
    skel->links.do_stack = bpf_program__attach_kprobe(skel->progs.do_stack, false, sym.name.c_str());
    return 0;
}

void OffCPUStackCollector::finish(void)
{
    DETACH_PROTO;
    UNLOAD_PROTO;
}

void OffCPUStackCollector::activate(bool tf)
{
    ACTIVE_SET(tf);
}

const char *OffCPUStackCollector::getName(void)
{
    return "OffCPUStackCollector";
}