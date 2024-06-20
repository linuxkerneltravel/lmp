// Copyright 2023 The LMP Authors.
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
// author: zai953879556@163.com
//
// mem_watcher libbpf kernel mode code

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mem_watcher.h"

const volatile __u64 stack_flags = 0;
 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t); // pid
    __type(value, u64); // size for alloc
} sizes SEC(".maps");
 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, ALLOCS_MAX_ENTRIES);
    __type(key, u64); /* alloc return address */
    __type(value, struct alloc_info);
} allocs SEC(".maps");

/* value： stack id 对应的堆栈的深度
 * max_entries: 最大允许存储多少个stack_id（每个stack id都对应一个完整的堆栈）
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
    __type(key, u64); /* stack id */
    __type(value, union combined_alloc_info);
} combined_allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    //__uint(max_entries, xxx); memleak_bpf__open 之后再动态设置
    __type(key, u32); /* stack id */
    //__type(value, xxx);       memleak_bpf__open 之后再动态设置
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); // pid
    __type(value, u64); // 用户态指针变量 memptr
} memptrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); /* alloc return address */
    __type(value, u64); /* timestamp */
    __uint(max_entries, 10240);
} addr_times SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); /* alloc return address */
    __type(value, u64); /* timestamp */
    __uint(max_entries, 10240);
} first_time SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static int gen_alloc_enter(size_t size) {
    const pid_t pid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);

    return 0;
}

static int gen_alloc_exit2(void *ctx, u64 address) {
    const u64 addr = (u64)address;
    const pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct alloc_info info;

    const u64 *size = bpf_map_lookup_elem(&sizes, &pid);
    if (NULL == size) {
        return 0;
    }

    __builtin_memset(&info, 0, sizeof(info));
    info.size = *size;

    bpf_map_delete_elem(&sizes, &pid);

    if (0 != address) {
        info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);

        bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);

        // Initialize the addr_times map to 0
        __u64 zero_ts = 0;
        bpf_map_update_elem(&addr_times, &addr, &zero_ts, BPF_ANY);

        union combined_alloc_info add_cinfo = {
            .total_size = info.size,
            .number_of_allocs = 1
        };

        union combined_alloc_info *exist_cinfo = bpf_map_lookup_elem(&combined_allocs, &info.stack_id);
        if (NULL == exist_cinfo) {
            bpf_map_update_elem(&combined_allocs, &info.stack_id, &add_cinfo, BPF_NOEXIST);
        }
        else {
            __sync_fetch_and_add(&exist_cinfo->bits, add_cinfo.bits);
        }
    }

    return 0;
}

static int gen_alloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static int gen_free_enter(const void *address) {
    const u64 addr = (u64)address;

    const struct alloc_info *info = bpf_map_lookup_elem(&allocs, &addr);
    if (NULL == info) {
        return 0;
    }

    union combined_alloc_info *exist_cinfo = bpf_map_lookup_elem(&combined_allocs, &info->stack_id);
    if (NULL == exist_cinfo) {
        return 0;
    }

    const union combined_alloc_info sub_cinfo = {
        .total_size = info->size,
        .number_of_allocs = 1
    };

    __sync_fetch_and_sub(&exist_cinfo->bits, sub_cinfo.bits);

    bpf_map_delete_elem(&allocs, &addr);

    // Initialize the addr_times map to 0
    __u64 zero_ts = 0;
    bpf_map_update_elem(&addr_times, &addr, &zero_ts, BPF_ANY);

    return 0;
}

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size) {
    return gen_alloc_enter(size);
}
 
SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit) {
    return gen_alloc_exit(ctx);
}
 
SEC("uprobe")
int BPF_KPROBE(free_enter, void *address) {
    return gen_free_enter(address);
}

SEC("uprobe")
int BPF_KPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size) {
    const u64 memptr64 = (u64)(size_t)memptr;
    const u64 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);

    return gen_alloc_enter(size);
}
 
SEC("uretprobe")
int BPF_KRETPROBE(posix_memalign_exit) {
    const u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *memptr64;
    void *addr;

    memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
    if (!memptr64)
        return 0;

    bpf_map_delete_elem(&memptrs, &pid);

    //通过 bpf_probe_read_user 读取保存在用户态指针变量(memptr64)中的分配的内存指针
    if (bpf_probe_read_user(&addr, sizeof(void *), (void *)(size_t)*memptr64))
        return 0;

    const u64 addr64 = (u64)(size_t)addr;

    return gen_alloc_exit2(ctx, addr64);
}
 
SEC("uprobe")
int BPF_KPROBE(calloc_enter, size_t nmemb, size_t size) {
    return gen_alloc_enter(nmemb * size);
}
 
SEC("uretprobe")
int BPF_KRETPROBE(calloc_exit) {
    return gen_alloc_exit(ctx);
}
 
SEC("uprobe")
int BPF_KPROBE(realloc_enter, void *ptr, size_t size) {
    gen_free_enter(ptr);

    return gen_alloc_enter(size);
}
 
SEC("uretprobe")
int BPF_KRETPROBE(realloc_exit) {
    return gen_alloc_exit(ctx);
}
 
SEC("uprobe")
int BPF_KPROBE(mmap_enter, void *address, size_t size) {
    return gen_alloc_enter(size);
}
 
SEC("uretprobe")
int BPF_KRETPROBE(mmap_exit) {
    return gen_alloc_exit(ctx);
}
 
SEC("uprobe")
int BPF_KPROBE(munmap_enter, void *address) {
    return gen_free_enter(address);
}
 
SEC("uprobe")
int BPF_KPROBE(aligned_alloc_enter, size_t alignment, size_t size) {
    return gen_alloc_enter(size);
}
 
SEC("uretprobe")
int BPF_KRETPROBE(aligned_alloc_exit) {
    return gen_alloc_exit(ctx);
}
 
SEC("uprobe")
int BPF_KPROBE(valloc_enter, size_t size) {
    return gen_alloc_enter(size);
}
 
SEC("uretprobe")
int BPF_KRETPROBE(valloc_exit) {
    return gen_alloc_exit(ctx);
}
 
SEC("uprobe")
int BPF_KPROBE(memalign_enter, size_t alignment, size_t size) {
    return gen_alloc_enter(size);
}
 
SEC("uretprobe")
int BPF_KRETPROBE(memalign_exit) {
    return gen_alloc_exit(ctx);
}
 
SEC("uprobe")
int BPF_KPROBE(pvalloc_enter, size_t size) {
    return gen_alloc_enter(size);
}
 
SEC("uretprobe")
int BPF_KRETPROBE(pvalloc_exit) {
    return gen_alloc_exit(ctx);
}

struct trace_event_raw_kmem_alloc_node___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

static __always_inline bool has_kmem_alloc_node(void) {
    if (bpf_core_type_exists(struct trace_event_raw_kmem_alloc_node___x))
        return true;
    return false;
}

struct trace_event_raw_kmem_alloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmalloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmem_cache_alloc___x {
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

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmalloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	gen_alloc_enter(bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmalloc_node")
int memleak__kmalloc_node(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		gen_alloc_enter( bytes_alloc);

		return gen_alloc_exit2(ctx, (u64)ptr);
	} else {
		/* tracepoint is disabled if not exist, avoid compile warning */
		return 0;
	}
}

struct trace_event_raw_kmem_free___x {
	const void *ptr;
} __attribute__((preserve_access_index));

struct trace_event_raw_kfree___x {
	const void *ptr;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmem_cache_free___x {
	const void *ptr;
} __attribute__((preserve_access_index));

static __always_inline bool has_kfree()
{
	if (bpf_core_type_exists(struct trace_event_raw_kfree___x))
		return true;
	return false;
}

static __always_inline bool has_kmem_cache_free()
{
	if (bpf_core_type_exists(struct trace_event_raw_kmem_cache_free___x))
		return true;
	return false;
}

SEC("tracepoint/kmem/kfree")
int memleak__kfree(void *ctx)
{
	const void *ptr;

	if (has_kfree()) {
		struct trace_event_raw_kfree___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int memleak__kmem_cache_alloc(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmem_cache_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	gen_alloc_enter(bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int memleak__kmem_cache_alloc_node(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		gen_alloc_enter(bytes_alloc);

		return gen_alloc_exit2(ctx, (u64)ptr);
	} else {
		/* tracepoint is disabled if not exist, avoid compile warning */
		return 0;
	}
}

SEC("tracepoint/kmem/kmem_cache_free")
int memleak__kmem_cache_free(void *ctx)
{
	const void *ptr;

	if (has_kmem_cache_free()) {
		struct trace_event_raw_kmem_cache_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/mm_page_alloc")
int memleak__mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
	gen_alloc_enter(4096 << ctx->order);

	return gen_alloc_exit2(ctx, ctx->pfn);
}

SEC("tracepoint/kmem/mm_page_free")
int memleak__mm_page_free(struct trace_event_raw_mm_page_free *ctx)
{
	return gen_free_enter((void *)ctx->pfn);
}