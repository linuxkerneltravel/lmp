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
// 内核态ebpf的内存模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ebpf.h"
#include "task.h"
#include "bpf_wapper/memleak.h"

COMMON_MAPS(union combined_alloc_info);
COMMON_VALS;
const volatile bool wa_missing_free = false;
const volatile size_t page_size = 4096;
const volatile bool trace_all = false;

BPF_HASH(pid_size_map, u32, u64, MAX_ENTRIES);             // 记录了对应进程使用malloc,calloc等函数申请内存的大小
BPF_HASH(piddr_meminfo_map, piddr, mem_info, MAX_ENTRIES); // 记录了每次申请的内存空间的起始地址等信息
BPF_HASH(memptrs_map, u32, u64, MAX_ENTRIES);

const char LICENSE[] SEC("license") = "GPL";

static int gen_alloc_enter(size_t size)
{
    CHECK_ACTIVE;
    CHECK_FREQ(TS);
    struct task_struct *curr = GET_CURR;
    CHECK_KTHREAD(curr);
    // attach 时已设置目标tgid，这里无需再次过滤tgid
    struct kernfs_node *knode = GET_KNODE(curr);
    CHECK_CGID(knode);

    u32 tgid = BPF_CORE_READ(curr, tgid);
    TRY_SAVE_INFO(curr, tgid, tgid, knode);
    if (trace_all)
        bpf_printk("alloc entered, size = %lu\n", size);
    // record size
    return bpf_map_update_elem(&pid_size_map, &tgid, &size, BPF_ANY);
}

static int gen_alloc_exit2(void *ctx, u64 addr)
{
    CHECK_ACTIVE;
    if (!addr)
        return 0;
    u32 tgid = bpf_get_current_pid_tgid();
    u64 *size = bpf_map_lookup_elem(&pid_size_map, &tgid);
    if (!size)
        return 0;
    // record counts
    psid apsid = TRACE_AND_GET_COUNT_KEY(tgid, ctx);
    union combined_alloc_info *count = bpf_map_lookup_elem(&psid_count_map, &apsid);
    union combined_alloc_info cur = {
        .number_of_allocs = 1,
        .total_size = *size,
    };
    if (!count)
        bpf_map_update_elem(&psid_count_map, &apsid, &cur, BPF_NOEXIST);
    else
        __sync_fetch_and_add(&(count->bits), cur.bits);
    if (trace_all)
        bpf_printk("alloc exited, size = %lu, result = %lx\n", *size, addr);
    // record pid_addr-info
    piddr a = {
        .addr = addr,
        .pid = tgid,
        ._pad = 0,
    };
    mem_info info = {
        .size = *size,
        .usid = apsid.usid,
        .ksid = apsid.ksid,
    };
    return bpf_map_update_elem(&piddr_meminfo_map, &a, &info, BPF_NOEXIST);
}

static int gen_alloc_exit(struct pt_regs *ctx)
{
    return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static int gen_free_enter(const void *addr)
{
    CHECK_ACTIVE;
    u32 tgid = bpf_get_current_pid_tgid();
    piddr a = {.addr = (u64)addr, .pid = tgid, ._pad = 0};
    mem_info *info = bpf_map_lookup_elem(&piddr_meminfo_map, &a);
    if (!info)
        return 0;

    // get allocated size
    psid apsid = {
        .pid = tgid,
        .ksid = info->ksid,
        .usid = info->usid,
    };

    union combined_alloc_info *size = bpf_map_lookup_elem(&psid_count_map, &apsid);
    if (!size)
        return -1;
    union combined_alloc_info cur = {
        .number_of_allocs = 1,
        .total_size = info->size,
    };
    // sub the freeing size
    __sync_fetch_and_sub(&(size->bits), cur.bits);

    if (size->total_size == 0)
        bpf_map_delete_elem(&psid_count_map, &apsid);
    if (trace_all)
        bpf_printk("free entered, address = %lx, size = %lu\n", addr, info->size);
    // del freeing addr info
    return bpf_map_delete_elem(&piddr_meminfo_map, &a);
}

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(calloc_enter, size_t nmemb, size_t size)
{
    return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe")
int BPF_KRETPROBE(calloc_exit)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(realloc_enter, void *ptr, size_t size)
{
    gen_free_enter(ptr);
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(realloc_exit)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size)
{
    const u64 memptr64 = (u64)(size_t)memptr;
    const u32 tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&memptrs_map, &tgid, &memptr64, BPF_ANY);
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(posix_memalign_exit)
{
    const u32 tgid = bpf_get_current_pid_tgid();
    u64 *memptr64 = bpf_map_lookup_elem(&memptrs_map, &tgid);
    if (!memptr64)
        return 0;
    bpf_map_delete_elem(&memptrs_map, &tgid);
    void *addr;
    if (bpf_probe_read_user(&addr, sizeof(void *), (void *)(size_t)*memptr64))
        return 0;
    const u64 addr64 = (u64)(size_t)addr;
    return gen_alloc_exit2(ctx, addr64);
}

SEC("uprobe")
int BPF_KPROBE(aligned_alloc_enter, size_t alignment, size_t size)
{
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(aligned_alloc_exit)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(valloc_enter, size_t size)
{
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(valloc_exit)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(memalign_enter, size_t alignment, size_t size)
{
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(memalign_exit)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(pvalloc_enter, size_t size)
{
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(pvalloc_exit)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void *addr)
{
    return gen_free_enter(addr);
}

SEC("uprobe")
int BPF_KPROBE(mmap_enter)
{
    size_t size = PT_REGS_PARM2(ctx);
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(mmap_exit)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(munmap_enter, void *addr)
{
    return gen_free_enter(addr);
}

struct trace_event_raw_kmem_alloc___x
{
    const void *ptr;
    size_t bytes_alloc;
} __attribute__((preserve_access_index));
struct trace_event_raw_kmalloc___x
{
    const void *ptr;
    size_t bytes_alloc;
} __attribute__((preserve_access_index));
static __always_inline bool has_kmem_alloc(void)
{
    if (bpf_core_type_exists(struct trace_event_raw_kmem_alloc___x))
        return true;
    return false;
}

SEC("tracepoint/kmem/kmalloc")
int memleak__kmalloc(void *ctx)
{
    const void *ptr;
    size_t bytes_alloc;

    if (has_kmem_alloc())
    {
        struct trace_event_raw_kmem_alloc___x *args = ctx;
        ptr = BPF_CORE_READ(args, ptr);
        bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
    }
    else
    {
        struct trace_event_raw_kmalloc___x *args = ctx;
        ptr = BPF_CORE_READ(args, ptr);
        bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
    }

    if (wa_missing_free)
        gen_free_enter(ptr);

    gen_alloc_enter(bytes_alloc);

    return gen_alloc_exit2(ctx, (u64)ptr);
}

struct trace_event_raw_kmem_alloc_node___x
{
    const void *ptr;
    size_t bytes_alloc;
} __attribute__((preserve_access_index));
static __always_inline bool has_kmem_alloc_node(void)
{
    if (bpf_core_type_exists(struct trace_event_raw_kmem_alloc_node___x))
        return true;
    return false;
}

SEC("tracepoint/kmem/kmalloc_node")
int memleak__kmalloc_node(void *ctx)
{
    const void *ptr;
    size_t bytes_alloc;

    if (has_kmem_alloc_node())
    {
        struct trace_event_raw_kmem_alloc_node___x *args = ctx;
        ptr = BPF_CORE_READ(args, ptr);
        bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

        if (wa_missing_free)
            gen_free_enter(ptr);

        gen_alloc_enter(bytes_alloc);

        return gen_alloc_exit2(ctx, (u64)ptr);
    }
    else
    {
        /* tracepoint is disabled if not exist, avoid compile warning */
        return 0;
    }
}

struct trace_event_raw_kfree___x
{
    const void *ptr;
} __attribute__((preserve_access_index));
struct trace_event_raw_kmem_free___x
{
    const void *ptr;
} __attribute__((preserve_access_index));
static __always_inline bool has_kfree()
{
    if (bpf_core_type_exists(struct trace_event_raw_kfree___x))
        return true;
    return false;
}
SEC("tracepoint/kmem/kfree")
int memleak__kfree(void *ctx)
{
    const void *ptr;

    if (has_kfree())
    {
        struct trace_event_raw_kfree___x *args = ctx;
        ptr = BPF_CORE_READ(args, ptr);
    }
    else
    {
        struct trace_event_raw_kmem_free___x *args = ctx;
        ptr = BPF_CORE_READ(args, ptr);
    }

    return gen_free_enter(ptr);
}

struct trace_event_raw_kmem_cache_alloc___x
{
    const void *ptr;
    size_t bytes_alloc;
} __attribute__((preserve_access_index));

SEC("tracepoint/kmem/kmem_cache_alloc")
int memleak__kmem_cache_alloc(void *ctx)
{
    const void *ptr;
    size_t bytes_alloc;

    if (has_kmem_alloc())
    {
        struct trace_event_raw_kmem_alloc___x *args = ctx;
        ptr = BPF_CORE_READ(args, ptr);
        bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
    }
    else
    {
        struct trace_event_raw_kmem_cache_alloc___x *args = ctx;
        ptr = BPF_CORE_READ(args, ptr);
        bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
    }

    if (wa_missing_free)
        gen_free_enter(ptr);

    gen_alloc_enter(bytes_alloc);

    return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int memleak__kmem_cache_alloc_node(void *ctx)
{
    const void *ptr;
    size_t bytes_alloc;

    if (has_kmem_alloc_node())
    {
        struct trace_event_raw_kmem_alloc_node___x *args = ctx;
        ptr = BPF_CORE_READ(args, ptr);
        bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

        if (wa_missing_free)
            gen_free_enter(ptr);

        gen_alloc_enter(bytes_alloc);

        return gen_alloc_exit2(ctx, (u64)ptr);
    }
    else
    {
        /* tracepoint is disabled if not exist, avoid compile warning */
        return 0;
    }
}

struct trace_event_raw_kmem_cache_free___x
{
    const void *ptr;
} __attribute__((preserve_access_index));
static __always_inline bool has_kmem_cache_free()
{
    if (bpf_core_type_exists(struct trace_event_raw_kmem_cache_free___x))
        return true;
    return false;
}
SEC("tracepoint/kmem/kmem_cache_free")
int memleak__kmem_cache_free(void *ctx)
{
    const void *ptr;

    if (has_kmem_cache_free())
    {
        struct trace_event_raw_kmem_cache_free___x *args = ctx;
        ptr = BPF_CORE_READ(args, ptr);
    }
    else
    {
        struct trace_event_raw_kmem_free___x *args = ctx;
        ptr = BPF_CORE_READ(args, ptr);
    }

    return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/mm_page_alloc")
int memleak__mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
    gen_alloc_enter(page_size << ctx->order);

    return gen_alloc_exit2(ctx, ctx->pfn);
}

SEC("tracepoint/kmem/mm_page_free")
int memleak__mm_page_free(struct trace_event_raw_mm_page_free *ctx)
{
    return gen_free_enter((void *)(ctx->pfn));
}

SEC("tracepoint/percpu/percpu_alloc_percpu")
int memleak__percpu_alloc_percpu(struct trace_event_raw_percpu_alloc_percpu *ctx)
{
    gen_alloc_enter(ctx->size);

    return gen_alloc_exit2(ctx, (u64)(ctx->ptr));
}

SEC("tracepoint/percpu/percpu_free_percpu")
int memleak__percpu_free_percpu(struct trace_event_raw_percpu_free_percpu *ctx)
{
    return gen_free_enter(ctx->ptr);
}