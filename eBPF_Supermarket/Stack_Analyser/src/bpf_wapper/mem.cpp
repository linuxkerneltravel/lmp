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
// mem ebpf程序的包装类，实现接口和一些自定义方法

#include "bpf_wapper/mem.h"

double MemoryStackCollector::count_value(void *d)
{
    return *(uint64_t *)d;
}

MemoryStackCollector::MemoryStackCollector()
{
    kstack = false;
    showDelta = false;
    scale.Period = 1;
    scale.Type = "LeakedMomery";
    scale.Unit = "bytes";
};

int MemoryStackCollector::load(void)
{
    StackProgLoadOpen();
    return 0;
};

int MemoryStackCollector::attach(void)
{
    at_ent(skel, malloc, malloc_enter);
    at_ret(skel, malloc, malloc_exit);
    at_ent(skel, calloc, calloc_enter);
    at_ret(skel, calloc, calloc_exit);
    at_ent(skel, realloc, realloc_enter);
    at_ret(skel, realloc, realloc_exit);
    at_ent(skel, free, free_enter);

    at_ent(skel, mmap, mmap_enter);
    at_ret(skel, mmap, mmap_exit);
    at_ent(skel, munmap, munmap_enter);

    err = skel->attach(skel);
    CHECK_ERR(err, "Failed to attach BPF skeleton");
    return 0;
};

void MemoryStackCollector::detach(void)
{
    skel->detach(skel);
#define des(name)                            \
    if (skel->links.name)                    \
    {                                        \
        bpf_link__destroy(skel->links.name); \
    }

    des(malloc_enter);
    des(malloc_exit);
    des(calloc_enter);
    des(calloc_exit);
    des(realloc_enter);
    des(realloc_exit);
    des(free_enter);
    des(mmap_enter);
    des(mmap_exit);
    des(munmap_enter);
};

void MemoryStackCollector::unload(void)
{
    defaultUnload;
}