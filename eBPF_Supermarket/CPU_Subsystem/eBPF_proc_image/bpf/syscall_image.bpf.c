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
const volatile pid_t ignore_pid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);                    // 可根据自己的CPU核心数进行设置，这里设置为10
	__type(key, pid_t);
	__type(value,struct syscall_seq);
} proc_syscall SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 10240);
} syscall_rb SEC(".maps");

// 记录进程的系统调用序列
SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *args)
{
    pid_t pid = bpf_get_current_pid_tgid();

    if(pid!=ignore_pid && (target_pid==-1 || pid==target_pid)){
        struct syscall_seq * syscall_seq;

        syscall_seq = bpf_map_lookup_elem(&proc_syscall, &pid);
        if(!syscall_seq){
            return 0;
        }

        if(syscall_seq->count < MAX_SYSCALL_COUNT-1 && syscall_seq->count >= 0 && 
            syscall_seq->record_syscall+syscall_seq->count <= syscall_seq->record_syscall+MAX_SYSCALL_COUNT){
                syscall_seq->record_syscall[syscall_seq->count] = (int)args->id;
                syscall_seq->count ++;
        }else if(syscall_seq->count == MAX_SYSCALL_COUNT-1){
            syscall_seq->record_syscall[syscall_seq->count] = -1;
            syscall_seq->count = MAX_SYSCALL_COUNT;
        }
    }

    return 0;
}


// 以进程on_cpu为单位输出系统调用序列
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	pid_t next_pid = BPF_CORE_READ(next,pid);
	pid_t prev_pid = BPF_CORE_READ(prev,pid);
    u64 current_time = bpf_ktime_get_ns();

	// 输出prev进程的syscall_seq事件
    if(prev_pid!=ignore_pid && (target_pid==-1 || prev_pid==target_pid)){
        struct syscall_seq * prev_syscall_seq;

        prev_syscall_seq = bpf_map_lookup_elem(&proc_syscall, &prev_pid);
        if(prev_syscall_seq){
            struct syscall_seq* e;
            e = bpf_ringbuf_reserve(&syscall_rb, sizeof(*e), 0);
            if(!e)
                return 0;
            
            e->pid = prev_syscall_seq->pid;
            e->oncpu_time = prev_syscall_seq->oncpu_time;
            e->offcpu_time = current_time;
            e->count = prev_syscall_seq->count;
            for(int i=0; i<=prev_syscall_seq->count && i<=MAX_SYSCALL_COUNT-1; i++)
                e->record_syscall[i] = prev_syscall_seq->record_syscall[i];

            bpf_ringbuf_submit(e, 0);
            bpf_map_delete_elem(&proc_syscall, &prev_pid);
        }
    }

    // 记录next进程的开始时间
    if(next_pid!=ignore_pid && (target_pid==-1 || next_pid==target_pid)){
        struct syscall_seq next_syscall_seq = {};

        next_syscall_seq.pid = next_pid;
        next_syscall_seq.oncpu_time = current_time;

        bpf_map_update_elem(&proc_syscall, &next_pid, &next_syscall_seq, BPF_ANY);
    }

    return 0;
}