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
// Kernel space BPF program used for monitoring data for KVM IRQ event.
#ifndef __KVM_IRQ_H
#define __KVM_IRQ_H

#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64);
} irq_set_delay SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64);
} irq_inject_delay SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct timer_key);
    __type(value, struct timer_value);
} timer_map SEC(".maps");

static int entry_kvm_pic_set_irq(int irq) {
    if (irq < 0 || irq >= PIC_NUM_PINS) {
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    u32 irq_type = irq >> 3;
    bpf_map_update_elem(&irq_set_delay, &irq_type, &ts, BPF_ANY);
    return 0;
}

static int exit_kvm_pic_set_irq(struct kvm_pic *s, int irq, int ret, void *rb,
                                struct common_event *e) {
    u64 *ts;
    u32 irq_type = irq >> 3;
    ts = bpf_map_lookup_elem(&irq_set_delay, &irq_type);
    if (!ts) {
        return 0;
    }
    u64 time = bpf_ktime_get_ns();
    u64 delay = time - *ts;
    bpf_map_delete_elem(&irq_set_delay, &irq_type);
    RESERVE_RINGBUF_ENTRY(rb, e);
    bpf_probe_read_kernel(&e->irqchip_data.ret, sizeof(int), &ret);
    e->time = *ts;
    e->irqchip_data.delay = delay;
    e->irqchip_data.irqchip_type = KVM_IRQCHIP_PIC;
    e->process.pid = bpf_get_current_pid_tgid() >> 32;
    e->irqchip_data.chip = irq_type;
    e->irqchip_data.pin = irq & 7;
    bpf_probe_read_kernel(&e->irqchip_data.elcr, sizeof(u8),
                          &s->pics[irq_type].elcr);
    bpf_probe_read_kernel(&e->irqchip_data.imr, sizeof(u8),
                          &s->pics[irq_type].imr);
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static int entry_kvm_ioapic_set_irq(int irq) {
    if (irq < 0 || irq >= IOAPIC_NUM_PINS) {
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    u32 irq_nr;
    bpf_probe_read_kernel(&irq_nr, sizeof(u32), &irq);
    bpf_map_update_elem(&irq_set_delay, &irq_nr, &ts, BPF_ANY);
    return 0;
}

static int exit_kvm_ioapic_set_irq(struct kvm_ioapic *ioapic, int irq, int ret,
                                   void *rb, struct common_event *e) {
    u64 *ts;
    u32 irq_nr;
    bpf_probe_read_kernel(&irq_nr, sizeof(int), &irq);
    ts = bpf_map_lookup_elem(&irq_set_delay, &irq_nr);
    if (!ts) {
        return 0;
    }
    u64 time = bpf_ktime_get_ns();
    u64 delay = time - *ts;
    bpf_map_delete_elem(&irq_set_delay, &irq_nr);
    RESERVE_RINGBUF_ENTRY(rb, e);
    union kvm_ioapic_redirect_entry entry;
    bpf_probe_read_kernel(&entry, sizeof(union kvm_ioapic_redirect_entry),
                          &ioapic->redirtbl[irq_nr]);
    bpf_probe_read_kernel(&e->irqchip_data.ioapic_bits, sizeof(u64),
                          &entry.bits);
    bpf_probe_read_kernel(&e->irqchip_data.delay, sizeof(u64), &delay);
    bpf_probe_read_kernel(&e->irqchip_data.ret, sizeof(u64), &ret);
    e->irqchip_data.irqchip_type = KVM_IRQCHIP_IOAPIC;
    e->irqchip_data.pin = irq_nr;
    e->time = *ts;
    e->process.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static int entry_kvm_set_msi(struct kvm *kvm,
                             struct kvm_kernel_irq_routing_entry *routing_entry,
                             int level) {
    bool x2apic_format;
    bpf_probe_read_kernel(&x2apic_format, sizeof(bool),
                          &kvm->arch.x2apic_format);
    if (x2apic_format && (routing_entry->msi.address_hi & 0xff))
        return 0;
    if (!level)
        return 0;
    pid_t tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&irq_set_delay, &tid, &ts, BPF_ANY);
    return 0;
}

static int exit_kvm_set_msi(struct kvm *kvm,
                            struct kvm_kernel_irq_routing_entry *routing_entry,
                            void *rb, struct common_event *e) {
    struct msi_msg msg = {.address_lo = routing_entry->msi.address_lo,
                          .address_hi = routing_entry->msi.address_hi,
                          .data = routing_entry->msi.data};
    pid_t tid = (u32)bpf_get_current_pid_tgid();
    u64 *ts = bpf_map_lookup_elem(&irq_set_delay, &tid);
    if (!ts) {
        return 0;
    }
    bool x2apic_format;
    bpf_probe_read_kernel(&x2apic_format, sizeof(bool),
                          &kvm->arch.x2apic_format);
    u64 time = bpf_ktime_get_ns();
    u64 delay = time - *ts;
    bpf_map_delete_elem(&irq_set_delay, &tid);
    RESERVE_RINGBUF_ENTRY(rb, e);
    e->irqchip_data.delay = delay;
    e->irqchip_data.irqchip_type = KVM_MSI;
    e->irqchip_data.address =
        msg.address_lo | (x2apic_format ? (u64)msg.address_hi << 32 : 0);
    e->irqchip_data.data = msg.data;
    e->time = *ts;
    e->process.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static int entry_vmx_inject_irq(struct kvm_vcpu *vcpu) {
    u32 irq_nr;
    bool rei;
    bpf_probe_read_kernel(&irq_nr, sizeof(u32), &vcpu->arch.interrupt.nr);
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&irq_inject_delay, &irq_nr, &ts, BPF_ANY);
    return 0;
}

static int exit_vmx_inject_irq(struct kvm_vcpu *vcpu, void *rb,
                               struct common_event *e) {
    u32 irq_nr;
    bpf_probe_read_kernel(&irq_nr, sizeof(u32), &vcpu->arch.interrupt.nr);
    u64 *ts = bpf_map_lookup_elem(&irq_inject_delay, &irq_nr);
    if (!ts) {
        return 0;
    }
    u64 time = bpf_ktime_get_ns();
    u64 delay = time - *ts;
    bpf_map_delete_elem(&irq_inject_delay, &irq_nr);
    bool soft;
    bpf_probe_read_kernel(&soft, sizeof(bool), &vcpu->arch.interrupt.soft);
    RESERVE_RINGBUF_ENTRY(rb, e);
    e->time = *ts;
    e->process.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    e->irq_inject_data.delay = delay;
    e->irq_inject_data.irq_nr = irq_nr;
    e->irq_inject_data.soft = soft;
    bpf_probe_read_kernel(&e->irq_inject_data.vcpu_id, sizeof(u32),
                          &vcpu->vcpu_id);
    bpf_probe_read_kernel(&e->irq_inject_data.injections, sizeof(u64),
                          &vcpu->stat.irq_injections);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static int update_timer_map(struct kvm_timer *ktimer) {
    enum TimerMode {
        ONESHOT,
        PERIODIC,
        TSCDEADLINE,
    };

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 timer_mode;
    struct timer_value timer_value = {.counts = 1};

    bpf_probe_read_kernel(&timer_mode, sizeof(u32), &ktimer->timer_mode);
    enum TimerMode tm;
    if (timer_mode == APIC_LVT_TIMER_ONESHOT) {
        tm = ONESHOT;
    } else if (timer_mode == APIC_LVT_TIMER_PERIODIC) {
        tm = PERIODIC;
    } else if (timer_mode == APIC_LVT_TIMER_TSCDEADLINE) {
        tm = TSCDEADLINE;
    } else {
        return 0;
    }

    struct timer_key timer_key = {
        .pid = pid, .hv = ktimer->hv_timer_in_use, .timer_mode = tm};
    struct timer_value *tv_p;
    tv_p = bpf_map_lookup_elem(&timer_map, &timer_key);
    if (tv_p) {
        __sync_fetch_and_add(&tv_p->counts, 1);
    } else {
        bpf_map_update_elem(&timer_map, &timer_key, &timer_value, BPF_NOEXIST);
    }
    return 0;
}

static int trace_start_hv_timer(struct kvm_lapic *apic) {
    struct kvm_timer ktimer;
    bpf_probe_read_kernel(&ktimer, sizeof(struct kvm_timer),
                          &apic->lapic_timer);
    if (!ktimer.tscdeadline)  // 检查tscdeadline模式定时器是否过期
        return 0;
    return update_timer_map(&ktimer);
}

static int trace_start_sw_timer(struct kvm_lapic *apic) {
    struct kvm_timer ktimer;
    bpf_probe_read_kernel(&ktimer, sizeof(struct kvm_timer),
                          &apic->lapic_timer);
    return update_timer_map(&ktimer);
}

#endif /* __KVM_IRQ_H */