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
// Kernel space BPF program used for monitoring data for KVM IRQ.
#ifndef __KVM_IRQ_H
#define __KVM_IRQ_H

#include "kvm_watcher.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64);
} irq_delay SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u32);
} source_id SEC(".maps");

static int entry_kvm_pic_set_irq(int irq, int irq_source_id, pid_t vm_pid) {
    CHECK_PID(vm_pid);
    if (irq < 0 || irq >= PIC_NUM_PINS) {
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    u32 irq_type = irq >> 3;
    bpf_map_update_elem(&irq_delay, &irq_type, &ts, BPF_ANY);
    return 0;
}

static int exit_kvm_pic_set_irq(struct kvm_pic *s, int irq, int irq_source_id,
                                int level, int ret, void *rb,
                                struct common_event *e) {
    u64 *ts;
    u32 irq_type = irq >> 3;
    ts = bpf_map_lookup_elem(&irq_delay, &irq_type);
    if (!ts) {
        return 0;
    }
    u64 time = bpf_ktime_get_ns();
    u64 delay = time - *ts;
    bpf_map_delete_elem(&irq_delay, &irq_type);
    RESERVE_RINGBUF_ENTRY(rb, e);
    bpf_probe_read_kernel(&e->pic_data.ret, sizeof(int), &ret);
    e->time = *ts;
    e->pic_data.delay = delay;
    e->process.pid = bpf_get_current_pid_tgid() >> 32;
    e->pic_data.chip = irq_type;
    e->pic_data.pin = irq & 7;
    e->pic_data.ioapic = false;
    bpf_probe_read_kernel(&e->pic_data.elcr, sizeof(u8),
                          &s->pics[irq_type].elcr);
    bpf_probe_read_kernel(&e->pic_data.imr, sizeof(u8), &s->pics[irq_type].imr);
    bpf_probe_read_kernel(&e->pic_data.irq_source_id, sizeof(int),
                          &irq_source_id);
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static int entry_kvm_ioapic_set_irq(int irq, int irq_source_id, pid_t vm_pid) {
    CHECK_PID(vm_pid);
    if (irq < 0 || irq >= IOAPIC_NUM_PINS) {
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    u32 irq_nr, irq_s_id;
    bpf_probe_read_kernel(&irq_nr, sizeof(u32), &irq);
    bpf_probe_read_kernel(&irq_s_id, sizeof(u32), &irq_source_id);
    bpf_map_update_elem(&irq_delay, &irq_nr, &ts, BPF_ANY);
    bpf_map_update_elem(&source_id, &irq_nr, &irq_s_id, BPF_ANY);
    return 0;
}

static int exit_kvm_ioapic_set_irq(struct kvm_ioapic *ioapic, int irq,
                                   int irq_level, bool line_status, int ret,
                                   void *rb, struct common_event *e) {
    u64 *ts;
    u32 *irq_s_id;
    u32 irq_nr;
    bpf_probe_read_kernel(&irq_nr, sizeof(int), &irq);
    ts = bpf_map_lookup_elem(&irq_delay, &irq_nr);
    irq_s_id = bpf_map_lookup_elem(&source_id, &irq_nr);
    bpf_map_delete_elem(&source_id, &irq_nr);
    if (!ts || !irq_s_id) {
        return 0;
    }
    u64 time = bpf_ktime_get_ns();
    u64 delay = time - *ts;
    bpf_map_delete_elem(&irq_delay, &irq_nr);
    RESERVE_RINGBUF_ENTRY(rb, e);
    union kvm_ioapic_redirect_entry entry;
    bpf_probe_read_kernel(&entry, sizeof(union kvm_ioapic_redirect_entry),
                          &ioapic->redirtbl[irq_nr]);
    bpf_probe_read_kernel(&e->pic_data.ioapic_bits, sizeof(u64), &entry.bits);
    bpf_probe_read_kernel(&e->pic_data.delay, sizeof(u64), &delay);
    bpf_probe_read_kernel(&e->pic_data.ret, sizeof(u64), &ret);
    e->pic_data.irq_source_id = *irq_s_id;
    e->pic_data.ioapic = true;
    e->pic_data.pin = irq_nr;
    e->time = *ts;
    e->process.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* __KVM_IRQ_H */