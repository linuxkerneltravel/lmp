// Copyright 2024 The EBPF performance testing Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: yys2020haha@163.com
//
// Kernel space BPF program used for eBPF performance testing.
#ifndef __ANALYZE_MAP_H
#define __ANALYZE_MAP_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);//12KB
    __type(key, u32);
    __type(value,u64);
} hash_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value,u64);
} array_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value,u64);
} percpu_array_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value,u64);
} percpu_hash_map SEC(".maps");
//在内核态中将数据信息存入到相应的map中
volatile __u64 k = 0;
#define MAX_ENTRIES 1024
static int analyze_maps(struct trace_event_raw_sys_enter *args,void *rb,
                                 struct common_event *e){
    u32 idx,counts;
    u64 syscall_id = (u64)args->id;
    // 使用原子操作递增k，并获取递增前的值
    idx = __sync_fetch_and_add(&k, 1); 
    // 确保k在0到MAX_ENTRIES之间循环(避免同步问题)
    if (idx >= MAX_ENTRIES) {
        __sync_bool_compare_and_swap(&k, idx + 1, 0);
        idx = 0;
    }
    // 向hash、array类型的map中存入数据
    bpf_map_update_elem(&hash_map, &idx, &syscall_id, BPF_ANY);
    bpf_map_update_elem(&array_map, &idx, &syscall_id, BPF_ANY);
    bpf_map_update_elem(&percpu_array_map,&idx,&syscall_id,BPF_ANY);
    bpf_map_update_elem(&percpu_hash_map,&idx,&syscall_id,BPF_ANY);
    bpf_map_update_elem(&percpu_hash_map,&idx,&syscall_id,BPF_ANY);
    RESERVE_RINGBUF_ENTRY(rb, e);
    e->test_ringbuff.key = idx;
    e->test_ringbuff.value = syscall_id;
    bpf_ringbuf_submit(e, 0);
    bpf_printk("syscall_id = %llu\n", syscall_id);
    return 0;
}
#endif /* __ANALYZE_MAP_H */
