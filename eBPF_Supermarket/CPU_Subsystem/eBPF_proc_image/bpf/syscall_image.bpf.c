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
// eBPF kernel-mode code that collects process syscalls

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t target_pid = -1;
const volatile int syscalls = 0;
const volatile pid_t ignore_tgid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value,struct syscall_seq);
} proc_syscall SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 10240);
} syscall_rb SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *args)
{
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if(tgid!=ignore_tgid && (target_pid==-1 || pid==target_pid)){
        u64 current_time = bpf_ktime_get_ns();
        struct syscall_seq * syscall_seq;

        syscall_seq = bpf_map_lookup_elem(&proc_syscall, &pid);
        if(!syscall_seq){
            struct syscall_seq syscall_seq = {};

            syscall_seq.pid = pid;
            syscall_seq.enter_time = current_time;
            syscall_seq.count = 1;
            syscall_seq.record_syscall[0] = (int)args->id;
            
            bpf_map_update_elem(&proc_syscall, &pid, &syscall_seq, BPF_ANY);
        }else if(syscall_seq->count < syscalls){
            syscall_seq->enter_time = current_time;

            if(syscall_seq->count <= MAX_SYSCALL_COUNT-1 && syscall_seq->count > 0 && 
                syscall_seq->record_syscall+syscall_seq->count <= syscall_seq->record_syscall+(MAX_SYSCALL_COUNT-1)){
                    syscall_seq->record_syscall[syscall_seq->count] = (int)args->id;
                    syscall_seq->count ++;
            }

            bpf_map_update_elem(&proc_syscall, &pid, syscall_seq, BPF_ANY);
        }
    }

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *args)
{
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if(tgid!=ignore_tgid && (target_pid==-1 || pid==target_pid)){
        u64 current_time = bpf_ktime_get_ns();
        long long unsigned int this_delay;
        struct syscall_seq * syscall_seq;

        syscall_seq = bpf_map_lookup_elem(&proc_syscall, &pid);
        if(!syscall_seq){
            return 0;
        }
        
        this_delay = current_time-syscall_seq->enter_time;

        if(syscall_seq->count < syscalls){
            syscall_seq->sum_delay += this_delay;
            if(this_delay > syscall_seq->max_delay)
                syscall_seq->max_delay = this_delay;

            bpf_map_update_elem(&proc_syscall, &pid, syscall_seq, BPF_ANY);
        }else{
            syscall_seq->sum_delay += this_delay;
            if(this_delay > syscall_seq->max_delay)
                syscall_seq->max_delay = this_delay;

            struct syscall_seq* e;
            e = bpf_ringbuf_reserve(&syscall_rb, sizeof(*e), 0);
            if(!e)
                return 0;
            
            e->pid = syscall_seq->pid;
            e->sum_delay = syscall_seq->sum_delay;
            e->max_delay = syscall_seq->max_delay;
            e->count = syscall_seq->count;
            for(int i=0; i<=syscall_seq->count-1 && i<=MAX_SYSCALL_COUNT-1; i++)
                e->record_syscall[i] = syscall_seq->record_syscall[i];
            
            bpf_ringbuf_submit(e, 0);
            bpf_map_delete_elem(&proc_syscall, &pid);
        }
    }

    return 0;
}