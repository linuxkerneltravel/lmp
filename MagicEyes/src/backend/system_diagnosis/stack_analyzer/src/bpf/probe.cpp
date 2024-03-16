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
// author: GaoYixiang
//
// probe ebpf 程序的包装类，实现接口和一些自定义方法

#include "bpf/probe.h"

double StackCountStackCollector::count_value(void *data) {
    return *(uint32_t*)data;
}

StackCountStackCollector::StackCountStackCollector()
{
    scale = {
        .Type = "StackCounts",
        .Unit = "Counts",
        .Period = 1,
    };
};

void StackCountStackCollector::setScale(std::string probe)
{
    this->probe = probe;
    scale.Type = (probe + scale.Type).c_str();
};

int StackCountStackCollector::load(void)
{
    StackProgLoadOpen();
    return 0;
};

int StackCountStackCollector::attach(void)
{
    skel->links.handle =
        bpf_program__attach_kprobe(skel->progs.handle, false, probe.c_str());
    CHECK_ERR(!skel->links.handle, "Fail to attach kprobe");
    return 0;
};

void StackCountStackCollector::detach(void)
{
    defaultDetach;
};

void StackCountStackCollector::unload(void)
{
    defaultUnload;
};
