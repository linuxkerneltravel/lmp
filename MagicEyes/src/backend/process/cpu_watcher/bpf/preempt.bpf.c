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
// author: albert_xuu@163.com zhangxy1016304@163.com zhangziheng0525@163.com

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "cpu_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TIF_NEED_RESCHED 3
const int ctrl_key = 0;
// 记录时间戳
BPF_HASH(preemptTime, pid_t, u64, 4096);
BPF_ARRAY(preempt_ctrl_map,int,struct preempt_ctrl,1);
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline struct preempt_ctrl *get_preempt_ctrl(void) {
    struct preempt_ctrl *preempt_ctrl;
    preempt_ctrl = bpf_map_lookup_elem(&preempt_ctrl_map, &ctrl_key);
    if (!preempt_ctrl || !preempt_ctrl->preempt_func) {
        return NULL;
    }
    return preempt_ctrl;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next) {
    struct preempt_ctrl *preempt_ctrl = get_preempt_ctrl();
    u64 start_time = bpf_ktime_get_ns();
    pid_t prev_pid = BPF_CORE_READ(prev, pid);
    
    if (preempt) {
        bpf_map_update_elem(&preemptTime, &prev_pid, &start_time, BPF_ANY);
    }
    
    // 下面的代码被注释掉，因为我们使用`preempt`参数判断是否需要记录时间戳
    // if (prev->thread_info.flags & TIF_NEED_RESCHED) {
    //     bpf_map_update_elem(&preemptTime, &prev_pid, &start_time, BPF_ANY);
    // }
    
    return 0;
}

// SEC("kprobe/finish_task_switch") 
SEC("kprobe/finish_task_switch.isra.0") 
int BPF_KPROBE(finish_task_switch, struct task_struct *prev) {
    struct preempt_ctrl *preempt_ctrl = get_preempt_ctrl();
    u64 end_time = bpf_ktime_get_ns();
    pid_t pid = BPF_CORE_READ(prev, pid);
    u64 *val;
    val = bpf_map_lookup_elem(&preemptTime, &pid);
    if (val) {
        u64 delta = end_time - *val;
        struct preempt_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e) {
            return 0;
        }   
        e->prev_pid = pid;
        e->next_pid = bpf_get_current_pid_tgid() >> 32;
        e->duration = delta;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
        bpf_map_delete_elem(&preemptTime, &pid);    
    }
    
    return 0;
}
