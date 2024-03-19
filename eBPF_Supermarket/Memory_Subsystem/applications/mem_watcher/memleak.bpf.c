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
#include "mem_watcher.h"
 
#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)
 
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
 
char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
    const pid_t pid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);

    return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit, void *address) {
    const u64 addr = (u64)address;
    const pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct alloc_info info;

    const u64 *size = bpf_map_lookup_elem(&sizes, &pid);
    if (size == NULL) {
        return 0;
    }

    __builtin_memset(&info, 0, sizeof(info));
    info.size = *size;

    bpf_map_delete_elem(&sizes, &pid);

    if (address != NULL) {
        info.stack_id = bpf_get_stackid(ctx, &stack_traces, USER_STACKID_FLAGS);

        bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);

        union combined_alloc_info add_cinfo = {
            .total_size = info.size,
            .number_of_allocs = 1
        };

        union combined_alloc_info *exist_cinfo = bpf_map_lookup_elem(&combined_allocs, &info.stack_id);
        if (exist_cinfo == NULL) {
            bpf_map_update_elem(&combined_allocs, &info.stack_id, &add_cinfo, BPF_NOEXIST);
        }
        else {
            __sync_fetch_and_add(&exist_cinfo->bits, add_cinfo.bits);
        }
    }

    return 0;
}
 
SEC("uprobe")
int BPF_KPROBE(free_enter, void * address)
{
    const u64 addr = (u64)address;
 
    const struct alloc_info * info = bpf_map_lookup_elem(&allocs, &addr);
    if (info == NULL) {
        return 0;
    }
 
    union combined_alloc_info * exist_cinfo = bpf_map_lookup_elem(&combined_allocs, &info->stack_id);
    if (exist_cinfo == NULL) {
        return 0;
    }
 
    const union combined_alloc_info sub_cinfo = {
        .total_size = info->size,
        .number_of_allocs = 1
    };
 
    __sync_fetch_and_sub(&exist_cinfo->bits, sub_cinfo.bits);
 
    bpf_map_delete_elem(&allocs, &addr);
 
    return 0;
}