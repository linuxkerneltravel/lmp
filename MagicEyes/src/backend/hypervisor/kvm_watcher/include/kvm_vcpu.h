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
// author: nanshuaibo811@163.com
//
// Kernel space BPF program used for monitoring data for vCPU.

#ifndef __KVM_VCPU_H
#define __KVM_VCPU_H

#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct vcpu_wakeup {
    u64 pad;
    __u64 ns;
    bool waited;
    bool valid;
};

struct halt_poll_ns {
    u64 pad;
    bool grow;
    unsigned int vcpu_id;
    unsigned int new;
    unsigned int old;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128 * 1024);
    __type(key, struct dirty_page_info);
    __type(value, u32);
} count_dirty_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u32);
} vcpu_tid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct load_key);
    __type(value, struct load_value);
} load_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct load_key);
    __type(value, struct time_value);
} load_time SEC(".maps");

// 记录vcpu_halt的id信息
static int trace_kvm_vcpu_halt(struct kvm_vcpu *vcpu) {
    u32 tid = bpf_get_current_pid_tgid();
    u32 vcpu_id;
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu->vcpu_id), &vcpu->vcpu_id);
    bpf_map_update_elem(&vcpu_tid, &tid, &vcpu_id, BPF_ANY);
    return 0;
}
// 使用kvm_vcpu_halt记录的数据，来获取vcpu的启动信息
static int trace_kvm_vcpu_wakeup(struct vcpu_wakeup *ctx, void *rb,
                                 struct common_event *e) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    u32 *vcpu_id = bpf_map_lookup_elem(&vcpu_tid, &tid);
    if (!vcpu_id) {
        return 0;
    }
    RESERVE_RINGBUF_ENTRY(rb, e);
    u64 time = bpf_ktime_get_ns();
    e->vcpu_wakeup_data.waited = ctx->waited;
    e->process.pid = pid;
    e->process.tid = tid;
    e->vcpu_wakeup_data.dur_hlt_ns = ctx->ns;
    e->vcpu_wakeup_data.vcpu_id = *vcpu_id;
    e->time = time;
    e->vcpu_wakeup_data.valid = ctx->valid;
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static int trace_kvm_halt_poll_ns(struct halt_poll_ns *ctx, void *rb,
                                  struct common_event *e) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    RESERVE_RINGBUF_ENTRY(rb, e);
    u64 time = bpf_ktime_get_ns();
    e->process.pid = pid;
    e->process.tid = tid;
    e->time = time;
    e->halt_poll_data.grow = ctx->grow;
    e->halt_poll_data.old = ctx->old;
    e->halt_poll_data.new = ctx->new;
    e->halt_poll_data.vcpu_id = ctx->vcpu_id;
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 记录VCPU调度的信息--进调度
static int trace_vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    u64 time = bpf_ktime_get_ns();
    u32 vcpu_id;
    if (!vcpu) {
        return 0;
    }
    bpf_probe_read_kernel(&vcpu_id, sizeof(u32), &vcpu->vcpu_id);
    struct time_value time_value;
    __builtin_memset(&time_value, 0, sizeof(struct time_value));
    time_value.time = time;
    time_value.vcpu_id = vcpu_id;
    time_value.pcpu_id = cpu;
    struct load_key curr_load_key;
    __builtin_memset(&curr_load_key, 0, sizeof(struct load_key));
    curr_load_key.pid = pid;
    curr_load_key.tid = tid;
    bpf_map_update_elem(&load_time, &curr_load_key, &time_value, BPF_ANY);
    return 0;
}
// 记录VCPU调度的信息--出调度
static int trace_vmx_vcpu_put() {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    struct load_key load_key;
    __builtin_memset(&load_key, 0, sizeof(struct load_key));
    load_key.pid = pid;
    load_key.tid = tid;
    struct time_value *t_value;
    t_value = bpf_map_lookup_elem(&load_time, &load_key);
    if (!t_value) {
        return 0;
    }
    u64 duration = bpf_ktime_get_ns() - t_value->time;
    bpf_map_delete_elem(&load_time, &load_key);
    struct load_value *load_value;
    load_value = bpf_map_lookup_elem(&load_map, &load_key);
    if (load_value) {
        load_value->count++;
        load_value->total_time += duration;
        if (load_value->max_time < duration) {
            load_value->max_time = duration;
        }
        if (load_value->min_time > duration) {
            load_value->min_time = duration;
        }
        load_value->pcpu_id = t_value->pcpu_id;
        load_value->vcpu_id = t_value->vcpu_id;
    } else {
        struct load_value new_load_value = {.count = 1,
                                            .max_time = duration,
                                            .total_time = duration,
                                            .min_time = duration,
                                            .vcpu_id = t_value->vcpu_id,
                                            .pcpu_id = t_value->pcpu_id};
        bpf_map_update_elem(&load_map, &load_key, &new_load_value, BPF_ANY);
    }
    return 0;
}
static int trace_mark_page_dirty_in_slot(struct kvm *kvm,
                                         const struct kvm_memory_slot *memslot,
                                         gfn_t gfn, void *rb,
                                         struct common_event *e) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 flags;
    struct kvm_memory_slot *slot;
    bpf_probe_read_kernel(&slot, sizeof(memslot), &memslot);
    bpf_probe_read_kernel(&flags, sizeof(memslot->flags), &memslot->flags);
    if (slot &&
        (flags & KVM_MEM_LOG_DIRTY_PAGES)) {  // 检查memslot是否启用了脏页追踪
        u32 tid = bpf_get_current_pid_tgid();
        unsigned long base_gfn;
        RESERVE_RINGBUF_ENTRY(rb, e);
        u64 time = bpf_ktime_get_ns();
        e->process.pid = pid;
        e->process.tid = tid;
        e->time = time;
        e->mark_page_dirty_data.gfn = gfn;
        bpf_probe_read_kernel(&base_gfn, sizeof(memslot->base_gfn),
                              &memslot->base_gfn);
        e->mark_page_dirty_data.rel_gfn = gfn - base_gfn;
        bpf_probe_read_kernel(&e->mark_page_dirty_data.npages,
                              sizeof(memslot->npages), &memslot->npages);
        bpf_probe_read_kernel(&e->mark_page_dirty_data.userspace_addr,
                              sizeof(memslot->userspace_addr),
                              &memslot->userspace_addr);
        bpf_probe_read_kernel(&e->mark_page_dirty_data.slot_id,
                              sizeof(memslot->id), &memslot->id);
        short int s_id;
        bpf_probe_read_kernel(&s_id, sizeof(memslot->id), &memslot->id);
        bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
        struct dirty_page_info dirty_page_info = {
            .gfn = gfn, .slot_id = s_id, .rel_gfn = gfn - base_gfn, .pid = pid};
        u32 *count;
        count = bpf_map_lookup_elem(&count_dirty_map, &dirty_page_info);
        if (count) {
            *count += 1;
            bpf_map_update_elem(&count_dirty_map, &dirty_page_info, count,
                                BPF_ANY);
        } else {
            u32 init_count = 1;
            bpf_map_update_elem(&count_dirty_map, &dirty_page_info, &init_count,
                                BPF_ANY);
        }
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
#endif /* __KVM_VCPU_H */
