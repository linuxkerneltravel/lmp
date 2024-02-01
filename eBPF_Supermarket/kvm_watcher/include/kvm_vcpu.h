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

#include "kvm_watcher.h"
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
// 记录vcpu_halt的id信息
static int trace_kvm_vcpu_halt(struct kvm_vcpu *vcpu, pid_t vm_pid) {
    CHECK_PID(vm_pid);
    u32 tid = bpf_get_current_pid_tgid();
    u32 vcpu_id;
    bpf_probe_read_kernel(&vcpu_id, sizeof(vcpu->vcpu_id), &vcpu->vcpu_id);
    bpf_map_update_elem(&vcpu_tid, &tid, &vcpu_id, BPF_ANY);
    return 0;
}
// 使用kvm_vcpu_halt记录的数据，来获取vcpu的启动信息
static int trace_kvm_vcpu_wakeup(struct vcpu_wakeup *ctx, void *rb,
                                 struct common_event *e, pid_t vm_pid) {
    CHECK_PID(vm_pid);
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
                                  struct common_event *e, pid_t vm_pid) {
    CHECK_PID(vm_pid);
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

static int trace_mark_page_dirty_in_slot(struct kvm *kvm,
                                         const struct kvm_memory_slot *memslot,
                                         gfn_t gfn, void *rb,
                                         struct common_event *e, pid_t vm_pid) {
    CHECK_PID(vm_pid);
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
