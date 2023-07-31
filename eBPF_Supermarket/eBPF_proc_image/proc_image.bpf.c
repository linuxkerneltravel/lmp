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
// author: zhangziheng0525@163.com
//
// kernel-mode code for the process image

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, pid_t);
	__type(value, struct sleep_offcpu);
} sleep SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 1024);
} sleep_rb SEC(".maps");

SEC("kprobe/finish_task_switch.isra.0")
int kprobe__finish_task_switch(struct pt_regs *ctx)
{
    struct task_struct *prev = (struct task_struct *)PT_REGS_PARM1(ctx);
    struct task_struct *next = (struct task_struct *)bpf_get_current_task();
    pid_t pid = target_pid;
    
    if(BPF_CORE_READ(prev,pid) == pid){
        struct sleep_offcpu sleep_offcpu={};
        
        sleep_offcpu.offcpu_id = bpf_get_smp_processor_id();
        sleep_offcpu.offcpu_time = bpf_ktime_get_ns();

        if(bpf_map_update_elem(&sleep, &pid, &sleep_offcpu, BPF_ANY))
            return 0;
    }else if(BPF_CORE_READ(next,pid) == pid){
        struct sleep_offcpu *sleep_offcpu;

        sleep_offcpu = bpf_map_lookup_elem(&sleep, &pid);
        if (!sleep_offcpu)
            return 0;
        
        struct sleep_event *sleep_event;
        sleep_event = bpf_ringbuf_reserve(&sleep_rb, sizeof(*sleep_event), 0);
        if(!sleep_event)
            return 0;
        
        sleep_event->offcpu_id = sleep_offcpu->offcpu_id;
        sleep_event->offcpu_time = sleep_offcpu->offcpu_time;
        sleep_event->pid = pid;
        bpf_get_current_comm(&sleep_event->comm, sizeof(sleep_event->comm));
        sleep_event->oncpu_id = bpf_get_smp_processor_id();
        sleep_event->oncpu_time = bpf_ktime_get_ns();

        bpf_ringbuf_submit(sleep_event, 0);

        bpf_map_delete_elem(&sleep, &pid);
    }

    return 0;
}