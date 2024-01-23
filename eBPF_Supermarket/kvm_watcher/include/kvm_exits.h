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
// Kernel space BPF program used for counting VM exit reason.

#ifndef __KVM_EXITS_H
#define __KVM_EXITS_H

#include "kvm_watcher.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
//定义哈希结构，存储时间信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, struct reason_info);
} times SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u32);
} counts SEC(".maps");
//记录退出的信息
struct exit {
    u64 pad;
    unsigned int exit_reason;
    unsigned long guest_rip;
    u32 isa;
    u64 info1;
    u64 info2;
    u32 intr_info;
    u32 error_code;
    unsigned int vcpu_id;
};

int total = 0;
//记录vm_exit的原因以及时间
static int trace_kvm_exit(struct exit *ctx, pid_t vm_pid) {
    CHECK_PID(vm_pid);
    u64 id, ts;
    id = bpf_get_current_pid_tgid();
    pid_t tid = (u32)id;
    ts = bpf_ktime_get_ns();
    u32 reason;
    reason = (u32)ctx->exit_reason;
    struct reason_info reas = {};
    reas.reason = reason;
    reas.time = ts;
    u32 *count;
    count = bpf_map_lookup_elem(&counts, &reason);
    if (count) {
        (*count)++;
        reas.count = *count;
    } else {
        u32 new_count = 1;
        reas.count = new_count;
        bpf_map_update_elem(&counts, &reason, &new_count, BPF_ANY);
    }
    bpf_map_update_elem(&times, &tid, &reas, BPF_ANY);
    return 0;
}
//通过kvm_exit所记录的信息，来计算出整个处理的时间
static int trace_kvm_entry(void *rb, struct common_event *e) {
    struct reason_info *reas;
    pid_t pid, tid;
    u64 id, ts, *start_ts, duration_ns = 0;
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;
    reas = bpf_map_lookup_elem(&times, &tid);
    if (reas) {
        u32 reason;
        int count = 0;
        duration_ns = bpf_ktime_get_ns() - reas->time;
        bpf_map_delete_elem(&times, &tid);
        reason = reas->reason;
        count = reas->count;
        RESERVE_RINGBUF_ENTRY(rb, e);
        e->exit_data.reason_number = reason;
        e->process.pid = pid;
        e->process.tid = tid;
        e->exit_data.duration_ns = duration_ns;
        bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
        e->exit_data.total = ++total;
        e->exit_data.count = count;
        e->time = reas->time;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}
#endif /* __KVM_EXITS_H */
