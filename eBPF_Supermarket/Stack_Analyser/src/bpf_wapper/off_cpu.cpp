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
    scale.Period = 1 << 20;
    scale.Type = "OffCPUTime";
    scale.Unit = "nanoseconds";
};

double OffCPUStackCollector::count_value(void *data)
{
    return *(uint32_t *)data;
};

int OffCPUStackCollector::load(void)
{
    StackProgLoadOpen(skel->rodata->apid = pid;);
    return 0;
}

int OffCPUStackCollector::attach(void)
{
    symbol sym;
    sym.name = "finish_task_switch";
    if(!g_symbol_parser.complete_kernel_symbol(sym))
    {
        return -1;
    }
    skel->links.do_stack = bpf_program__attach_kprobe(skel->progs.do_stack, false, sym.name.c_str());
    return 0;
}

void OffCPUStackCollector::detach(void) {
    defaultDetach;
}

void OffCPUStackCollector::unload(void) {
    defaultUnload;
}