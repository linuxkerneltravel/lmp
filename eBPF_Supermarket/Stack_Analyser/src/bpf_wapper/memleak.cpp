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

#include "bpf_wapper/memleak.h"
#include "trace.h"
#include <cmath>

uint64_t *MemleakStackCollector::count_values(void *d)
{
    auto data = (combined_alloc_info *)d;
    return new uint64_t[scale_num]{
        data->total_size,
        data->number_of_allocs,
    };
}

MemleakStackCollector::MemleakStackCollector()
{
    showDelta = false;
    scale_num = 2;
    scales = new Scale[scale_num]{
        {"LeakedSize", 1, "bytes"},
        {"LeakedCount", 1, "counts"},
    };
};

static bool has_kernel_node_tracepoints()
{
    return tracepoint_exists("kmem", "kmalloc_node") &&
           tracepoint_exists("kmem", "kmem_cache_alloc_node");
}

static void disable_kernel_node_tracepoints(struct memleak_bpf *skel)
{
    bpf_program__set_autoload(skel->progs.memleak__kmalloc_node, false);
    bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc_node, false);
}

static void disable_kernel_percpu_tracepoints(struct memleak_bpf *skel)
{
    bpf_program__set_autoload(skel->progs.memleak__percpu_alloc_percpu, false);
    bpf_program__set_autoload(skel->progs.memleak__percpu_free_percpu, false);
}

static void disable_kernel_tracepoints(struct memleak_bpf *skel)
{
    bpf_program__set_autoload(skel->progs.memleak__kmalloc, false);
    bpf_program__set_autoload(skel->progs.memleak__kmalloc_node, false);
    bpf_program__set_autoload(skel->progs.memleak__kfree, false);
    bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc, false);
    bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc_node, false);
    bpf_program__set_autoload(skel->progs.memleak__kmem_cache_free, false);
    bpf_program__set_autoload(skel->progs.memleak__mm_page_alloc, false);
    bpf_program__set_autoload(skel->progs.memleak__mm_page_free, false);
    bpf_program__set_autoload(skel->progs.memleak__percpu_alloc_percpu, false);
    bpf_program__set_autoload(skel->progs.memleak__percpu_free_percpu, false);
}

int MemleakStackCollector::attach_uprobes(struct memleak_bpf *skel)
{
    ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);

    ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);

    ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);

    ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
    ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);

    ATTACH_UPROBE_CHECKED(skel, posix_memalign, posix_memalign_enter);
    ATTACH_URETPROBE_CHECKED(skel, posix_memalign, posix_memalign_exit);

    ATTACH_UPROBE_CHECKED(skel, memalign, memalign_enter);
    ATTACH_URETPROBE_CHECKED(skel, memalign, memalign_exit);

    ATTACH_UPROBE_CHECKED(skel, free, free_enter);
    ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);

    // the following probes are intentinally allowed to fail attachment

    // deprecated in libc.so bionic
    ATTACH_UPROBE(skel, valloc, valloc_enter);
    ATTACH_URETPROBE(skel, valloc, valloc_exit);

    // deprecated in libc.so bionic
    ATTACH_UPROBE(skel, pvalloc, pvalloc_enter);
    ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit);

    // added in C11
    ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter);
    ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit);

    return 0;
}

int MemleakStackCollector::ready(void)
{
    EBPF_LOAD_OPEN_INIT(
        if (kstack) {
            if (!has_kernel_node_tracepoints())
                disable_kernel_node_tracepoints(skel);
            if (!percpu)
                disable_kernel_percpu_tracepoints(skel);
        } else disable_kernel_tracepoints(skel);
        skel->rodata->wa_missing_free = wa_missing_free;
        skel->rodata->page_size = sysconf(_SC_PAGE_SIZE););
    if (!kstack)
        CHECK_ERR_RN1(attach_uprobes(skel), "failed to attach uprobes");
    err = skel->attach(skel);
    CHECK_ERR_RN1(err, "Failed to attach BPF skeleton");
    return 0;
}

void MemleakStackCollector::finish(void)
{
    DETACH_PROTO;
    UNLOAD_PROTO;
}


void MemleakStackCollector::activate(bool tf)
{
    ACTIVE_SET(tf);
}

const char *MemleakStackCollector::getName(void)
{
    return "MemleakStackCollector";
}
