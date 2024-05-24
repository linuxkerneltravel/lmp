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
// Kernel space BPF program used for monitoring data for KVM HYPERCALL.

#ifndef __KVM_HYPERCALL_H
#define __KVM_HYPERCALL_H

#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// 定义宏从寄存器读取超级调用信息
// 代码来源：arch/x86/kvm/kvm_cache_regs.h
#define BUILD_KVM_GPR_ACCESSORS(lname, uname)                \
    static __always_inline unsigned long kvm_##lname##_read( \
        struct kvm_vcpu *vcpu) {                             \
        return vcpu->arch.regs[VCPU_REGS_##uname];           \
    }

BUILD_KVM_GPR_ACCESSORS(rax, RAX)
BUILD_KVM_GPR_ACCESSORS(rbx, RBX)
BUILD_KVM_GPR_ACCESSORS(rcx, RCX)
BUILD_KVM_GPR_ACCESSORS(rdx, RDX)
BUILD_KVM_GPR_ACCESSORS(rsi, RSI)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct hc_key);
    __type(value, struct hc_value);
} hc_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct hc_key);
    __type(value, u32);
} hc_count SEC(".maps");

static int trace_emulate_hypercall(struct kvm_vcpu *vcpu, void *rb,
                                   struct common_event *e) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 nr, a0, a1, a2, a3;
    nr = kvm_rax_read(vcpu);  // 超级调用号
    // 超级调用参数
    a0 = kvm_rbx_read(vcpu);
    a1 = kvm_rcx_read(vcpu);
    a2 = kvm_rdx_read(vcpu);
    a3 = kvm_rsi_read(vcpu);
    RESERVE_RINGBUF_ENTRY(rb, e);
    e->process.pid = pid;
    e->process.tid = (u32)bpf_get_current_pid_tgid();
    e->time = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    e->hypercall_data.a0 = a0;
    e->hypercall_data.a1 = a1;
    e->hypercall_data.a2 = a2;
    e->hypercall_data.a3 = a3;
    e->hypercall_data.vcpu_id = vcpu->vcpu_id;
    e->hypercall_data.hc_nr = nr;
    e->hypercall_data.hypercalls = vcpu->stat.hypercalls;
    bpf_ringbuf_submit(e, 0);
    struct hc_key hc_key = {.pid = pid, .nr = nr, .vcpu_id = vcpu->vcpu_id};
    struct hc_value hc_value = {.a0 = a0,
                                .a1 = a1,
                                .a2 = a2,
                                .a3 = a3,
                                .counts = 1,
                                .hypercalls = vcpu->stat.hypercalls};
    u32 *count;
    count = bpf_map_lookup_elem(&hc_count, &hc_key);
    if (count) {
        __sync_fetch_and_add(count, 1);
        hc_value.counts = *count;
    } else {
        bpf_map_update_elem(&hc_count, &hc_key, &hc_value.counts, BPF_NOEXIST);
    }
    bpf_map_update_elem(&hc_map, &hc_key, &hc_value, BPF_ANY);
    return 0;
}

#endif /* __KVM_HYPERCALL_H */