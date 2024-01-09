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
// Kernel space BPF program used for monitoring data for KVM PIC.
#ifndef __KVM_PIC_H
#define __KVM_PIC_H

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

static int trace_in_kvm_pic_set_irq(struct kvm_pic *s, int irq,
                                    int irq_source_id, int level,
                                    pid_t vm_pid) {
    CHECK_PID(vm_pid) {
        if (irq < 0 || irq >= PIC_NUM_PINS) {
            return 0;
        }
        u64 ts = bpf_ktime_get_ns();
        u32 irq_type = irq >> 3;
        bpf_map_update_elem(&irq_delay, &irq_type, &ts, BPF_ANY);
    }
    return 0;
}

static int trace_out_kvm_pic_set_irq(struct kvm_pic *s, int irq,
                                     int irq_source_id, int level, int retval,
                                     void *rb, struct common_event *e) {
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
    e->pic_data.ret = retval;
    e->time = *ts;
    e->pic_data.delay = delay;
    e->process.pid = bpf_get_current_pid_tgid() >> 32;
    e->pic_data.chip = irq_type;
    e->pic_data.pin = irq & 7;
    bpf_probe_read_kernel(&e->pic_data.elcr, sizeof(u8),
                          &s->pics[irq_type].elcr);
    bpf_probe_read_kernel(&e->pic_data.imr, sizeof(u8), &s->pics[irq_type].imr);
    bpf_probe_read_kernel(&e->pic_data.irq_source_id, sizeof(int),
                          &irq_source_id);
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* __KVM_PIC_H */