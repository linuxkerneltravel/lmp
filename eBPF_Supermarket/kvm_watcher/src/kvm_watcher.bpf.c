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
// Kernel space BPF program used for monitoring data for KVM event.

#include "../include/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/kvm_watcher.h"
#include "../include/kvm_exits.h"
#include "../include/kvm_ioctl.h"
#include "../include/kvm_vcpu.h"
#include "../include/kvm_mmu.h"
#include "../include/kvm_irq.h"
#include "../include/kvm_hypercall.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t vm_pid = -1;
static struct common_event *e;

// 定义环形缓冲区maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 获取vcpu的id
SEC("fentry/kvm_vcpu_halt")
int BPF_PROG(fentry_kvm_vcpu_halt, struct kvm_vcpu *vcpu) {
    CHECK_PID(vm_pid);
    return trace_kvm_vcpu_halt(vcpu);
}
// 追踪vcpu运行信息
SEC("tp/kvm/kvm_vcpu_wakeup")
int tp_vcpu_wakeup(struct vcpu_wakeup *ctx) {
    return trace_kvm_vcpu_wakeup(ctx, &rb, e);
}
// 记录vcpu的halt_poll（暂停轮询）时间变化
SEC("tp/kvm/kvm_halt_poll_ns")
int tp_kvm_halt_poll_ns(struct halt_poll_ns *ctx) {
    CHECK_PID(vm_pid);
    return trace_kvm_halt_poll_ns(ctx, &rb, e);
}
// 记录vm_exit的时间
SEC("tp/kvm/kvm_exit")
int tp_exit(struct exit *ctx) {
    CHECK_PID(vm_pid);
    return trace_kvm_exit(ctx);
}
// 记录vm_entry和vm_exit的时间差
SEC("tp/kvm/kvm_entry")
int tp_entry(struct exit *ctx) {
    return trace_kvm_entry();
}
//记录VCPU调度的信息--进入
SEC("kprobe/vmx_vcpu_load")
int BPF_KPROBE(kp_vmx_vcpu_load, struct kvm_vcpu *vcpu, int cpu) {
    return trace_vmx_vcpu_load(vcpu, cpu);
}
//记录VCPU调度的信息--退出
SEC("kprobe/vmx_vcpu_put")
int BPF_KPROBE(kp_vmx_vcpu_put, struct kvm_vcpu *vcpu) {
    return trace_vmx_vcpu_put();
}
SEC("kprobe/mark_page_dirty_in_slot")
int BPF_KPROBE(kp_mark_page_dirty_in_slot, struct kvm *kvm,
               const struct kvm_memory_slot *memslot, gfn_t gfn) {
    CHECK_PID(vm_pid);
    return trace_mark_page_dirty_in_slot(kvm, memslot, gfn, &rb, e);
}

SEC("tp/kvm/kvm_page_fault")
int tp_page_fault(struct page_fault *ctx) {
    CHECK_PID(vm_pid);
    return trace_page_fault(ctx);
}

SEC("fexit/kvm_tdp_page_fault")
int BPF_PROG(fexit_tdp_page_fault, struct kvm_vcpu *vcpu,
             struct kvm_page_fault *fault) {
    return trace_tdp_page_fault(vcpu, fault, &rb, e);
}

SEC("fentry/kvm_mmu_page_fault")
int BPF_PROG(fentry_kvm_mmu_page_fault, struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa,
             u64 error_code) {
    CHECK_PID(vm_pid);
    return trace_kvm_mmu_page_fault(vcpu, cr2_or_gpa, error_code);
}

SEC("tp/kvmmmu/handle_mmio_page_fault")
int tp_handle_mmio_page_fault(struct mmio_page_fault *ctx) {
    return trace_handle_mmio_page_fault(ctx, &rb, e);
}

SEC("fentry/kvm_pic_set_irq")
int BPF_PROG(fentry_kvm_pic_set_irq, struct kvm_pic *s, int irq,
             int irq_source_id, int level) {
    CHECK_PID(vm_pid);
    return entry_kvm_pic_set_irq(irq);
}

SEC("fexit/kvm_pic_set_irq")
int BPF_PROG(fexit_kvm_pic_set_irq, struct kvm_pic *s, int irq,
             int irq_source_id, int level, int ret) {
    return exit_kvm_pic_set_irq(s, irq, ret, &rb, e);
}

SEC("fentry/ioapic_set_irq")
int BPF_PROG(fentry_kvm_ioapic_set_irq, struct kvm_ioapic *ioapic, int irq,
             int irq_level, bool line_status) {
    CHECK_PID(vm_pid);
    return entry_kvm_ioapic_set_irq(irq);
}

SEC("fexit/ioapic_set_irq")
int BPF_PROG(fexit_kvm_ioapic_set_irq, struct kvm_ioapic *ioapic, int irq,
             int irq_level, bool line_status, int ret) {
    return exit_kvm_ioapic_set_irq(ioapic, irq, ret, &rb, e);
}

SEC("fentry/kvm_set_msi")
int BPF_PROG(fentry_kvm_set_msi,
             struct kvm_kernel_irq_routing_entry *routing_entry,
             struct kvm *kvm, int irq_source_id, int level, bool line_status) {
    CHECK_PID(vm_pid);
    return entry_kvm_set_msi(kvm, routing_entry, level);
}

SEC("fexit/kvm_set_msi")
int BPF_PROG(fexit_kvm_set_msi,
             struct kvm_kernel_irq_routing_entry *routing_entry,
             struct kvm *kvm, int irq_source_id, int level, bool line_status) {
    return exit_kvm_set_msi(kvm, routing_entry, &rb, e);
}

SEC("fentry/vmx_inject_irq")
int BPF_PROG(fentry_vmx_inject_irq, struct kvm_vcpu *vcpu, bool reinjected) {
    CHECK_PID(vm_pid);
    return entry_vmx_inject_irq(vcpu);
}

SEC("fexit/vmx_inject_irq")
int BPF_PROG(fexit_vmx_inject_irq, struct kvm_vcpu *vcpu, bool reinjected) {
    return exit_vmx_inject_irq(vcpu, &rb, e);
}

SEC("fentry/kvm_emulate_hypercall")
int BPF_PROG(fentry_emulate_hypercall, struct kvm_vcpu *vcpu) {
    CHECK_PID(vm_pid);
    return entry_emulate_hypercall(vcpu, &rb, e);
}

SEC("tp/syscalls/sys_enter_ioctl")
int tp_ioctl(struct trace_event_raw_sys_enter *args) {
    CHECK_PID(vm_pid);
    return trace_kvm_ioctl(args);
}
SEC("fentry/kvm_arch_vcpu_ioctl_run")
int BPF_PROG(fentry_kvm_arch_vcpu_ioctl_run, struct kvm_vcpu *vcpu) {
    CHECK_PID(vm_pid);
    return trace_kvm_userspace_entry(vcpu);
}

SEC("tp/kvm/kvm_userspace_exit")
int tp_kvm_userspace_exit(struct userspace_exit *ctx) {
    return trace_kvm_userspace_exit(ctx);
}