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

#define EXIT_REASON_HLT 12

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct exit_key);      // exit_key:reason pid pad[2]
    __type(value, struct exit_value);  // exit_value : max_time total_time
                                       // min_time count pad
} exit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, struct reason_info);  // reason_info:time、reason、count
} times SEC(".maps");

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

static int trace_kvm_exit(struct exit *ctx, pid_t vm_pid) {
    CHECK_PID(vm_pid);
    u32 reason;
    reason = (u32)ctx->exit_reason;
    // 如果是节能停止退出，就不采集数据
    if (reason == EXIT_REASON_HLT) {
        return 0;
    }
    u64 id, ts;
    id = bpf_get_current_pid_tgid();
    pid_t tid = (u32)id;
    ts = bpf_ktime_get_ns();
    struct reason_info reas = {};
    reas.reason = reason;
    reas.time = ts;
    bpf_map_update_elem(&times, &tid, &reas, BPF_ANY);
    return 0;
}

static int trace_kvm_entry() {
    struct reason_info *reas;
    pid_t pid, tid;
    u64 id, ts, *start_ts, duration_ns;
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;
    reas = bpf_map_lookup_elem(&times, &tid);
    if (!reas) {
        return 0;
    }
    duration_ns = bpf_ktime_get_ns() - reas->time;
    bpf_map_delete_elem(&times, &tid);
    struct exit_key exit_key;
    __builtin_memset(&exit_key, 0, sizeof(struct exit_key));
    exit_key.pid = pid;
    exit_key.tid = tid;
    exit_key.reason = reas->reason;
    struct exit_value *exit_value;
    exit_value = bpf_map_lookup_elem(&exit_map, &exit_key);
    if (exit_value) {
        exit_value->count++;
        exit_value->total_time += duration_ns;
        if (exit_value->max_time < duration_ns) {
            exit_value->max_time = duration_ns;
        }
        if (exit_value->min_time > duration_ns) {
            exit_value->min_time = duration_ns;
        }
    } else {
        struct exit_value new_exit_value = {.count = 1,
                                            .max_time = duration_ns,
                                            .total_time = duration_ns,
                                            .min_time = duration_ns};
        bpf_map_update_elem(&exit_map, &exit_key, &new_exit_value, BPF_ANY);
    }
    return 0;
}
#endif /* __KVM_EXITS_H */
