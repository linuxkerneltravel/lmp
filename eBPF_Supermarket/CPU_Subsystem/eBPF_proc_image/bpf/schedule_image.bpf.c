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
// eBPF kernel-mode code that collects process schedule information

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t target_pid = -1;
const volatile int target_cpu_id = -1;
const volatile pid_t ignore_tgid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct proc_id);
	__type(value,struct schedule_event);
} proc_schedule SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct proc_id);
	__type(value,bool);
} enable_add SEC(".maps");

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    pid_t pid = BPF_CORE_READ(p,pid);
    int tgid = BPF_CORE_READ(p,tgid);
    int cpu = bpf_get_smp_processor_id();

    if(tgid!=ignore_tgid && (target_pid==-1 || (target_pid!=0 && pid==target_pid) || 
	   (target_pid==0 && pid==target_pid && cpu==target_cpu_id))){
        struct schedule_event *schedule_event;
        struct proc_id pd = {};
        u64 current_time = bpf_ktime_get_ns();

        pd.pid = pid;
        if(pid == 0)    pd.cpu_id = cpu;
        schedule_event = bpf_map_lookup_elem(&proc_schedule,&pd);
        if(!schedule_event){
            struct schedule_event schedule_event = {};
            bool e_add = false;
            
            schedule_event.pid = pid;
            // 提前将 count 值赋值为 1，避免输出时进程还没有被调度，导致除数出现 0 的情况
            schedule_event.count = 1;
            schedule_event.enter_time = current_time;

            bpf_map_update_elem(&enable_add,&pd,&e_add,BPF_ANY);
            bpf_map_update_elem(&proc_schedule,&pd,&schedule_event,BPF_ANY);
        }else{
            schedule_event->enter_time = current_time;
        }
    }

    return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
    pid_t pid = BPF_CORE_READ(p,pid);
    int tgid = BPF_CORE_READ(p,tgid);
    int cpu = bpf_get_smp_processor_id();

    if(tgid!=ignore_tgid && (target_pid==-1 || (target_pid!=0 && pid==target_pid) || 
	   (target_pid==0 && pid==target_pid && cpu==target_cpu_id))){
        struct schedule_event *schedule_event;
        struct proc_id pd = {};
        u64 current_time = bpf_ktime_get_ns();

        pd.pid = pid;
        if(pid == 0)    pd.cpu_id = cpu;
        schedule_event = bpf_map_lookup_elem(&proc_schedule,&pd);
        if(!schedule_event){
            struct schedule_event schedule_event = {};
            bool e_add = false;
            
            schedule_event.pid = pid;
            schedule_event.count = 1;
            schedule_event.enter_time = current_time;

            bpf_map_update_elem(&enable_add,&pd,&e_add,BPF_ANY);
            bpf_map_update_elem(&proc_schedule,&pd,&schedule_event,BPF_ANY);
        }else{
            schedule_event->enter_time = current_time;
        }
    }

    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    pid_t prev_pid = BPF_CORE_READ(prev,pid);
    int prev_tgid = BPF_CORE_READ(prev,tgid);
    int prev_cpu = bpf_get_smp_processor_id();
    unsigned int prev_state = BPF_CORE_READ(prev,__state);
    pid_t next_pid = BPF_CORE_READ(next,pid);
    int next_tgid = BPF_CORE_READ(next,tgid);
    int next_cpu = prev_cpu;
    u64 current_time = bpf_ktime_get_ns();
    
    if(prev_tgid!=ignore_tgid && prev_state==TASK_RUNNING && (target_pid==-1 || (target_pid!=0 && prev_pid==target_pid) || 
	   (target_pid==0 && prev_pid==target_pid && prev_cpu==target_cpu_id))){
        struct schedule_event *schedule_event;
        struct proc_id pd = {};

        pd.pid = prev_pid;
        if(prev_pid == 0)    pd.cpu_id = prev_cpu;
        schedule_event = bpf_map_lookup_elem(&proc_schedule,&pd);
        if(!schedule_event){
            struct schedule_event schedule_event = {};
            bool e_add = false;
            
            schedule_event.pid = prev_pid;
            schedule_event.count = 1;
            schedule_event.enter_time = current_time;

            bpf_map_update_elem(&enable_add,&pd,&e_add,BPF_ANY);
            bpf_map_update_elem(&proc_schedule,&pd,&schedule_event,BPF_ANY);
        }else{
            schedule_event->enter_time = current_time;
        }
    }

    if(next_tgid!=ignore_tgid && (target_pid==-1 || (target_pid!=0 && next_pid==target_pid) || 
	   (target_pid==0 && next_pid==target_pid && next_cpu==target_cpu_id))){
        struct schedule_event *schedule_event;
        bool * e_add;
        struct proc_id pd = {};
        u64 this_delay;

        pd.pid = next_pid;
        if(next_pid == 0)    pd.cpu_id = next_cpu;
        schedule_event = bpf_map_lookup_elem(&proc_schedule,&pd);
        if(!schedule_event)
            return 0;

        e_add = bpf_map_lookup_elem(&enable_add,&pd);
        if(!e_add)  return 0;
        // 因为 count 值初值赋值为了 1，避免多加一次
        if(*e_add)  schedule_event->count++;
        else    *e_add = true;
        this_delay = current_time-schedule_event->enter_time;

        schedule_event->prio = BPF_CORE_READ(next,prio);
        schedule_event->sum_delay += this_delay;
        if(this_delay > schedule_event->max_delay)
            schedule_event->max_delay = this_delay;
        if(schedule_event->min_delay==0 || this_delay<schedule_event->min_delay)
            schedule_event->min_delay = this_delay;
    }

    return 0;
}