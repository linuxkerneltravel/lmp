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

const int key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct sched_ctrl);
} sched_ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct proc_id);
	__type(value,struct schedule_event);
} proc_schedule SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value,struct schedule_event);
} target_schedule SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct proc_id);
	__type(value,bool);
} enable_add SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value,struct schedule_event);
} tg_schedule SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct sum_schedule);
} sys_schedule SEC(".maps");

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    struct sched_ctrl *sched_ctrl;
	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
	if(!sched_ctrl || !sched_ctrl->sched_func)
		return 0;
    
    pid_t pid = BPF_CORE_READ(p,pid);
    int tgid = BPF_CORE_READ(p,tgid);
    int cpu = bpf_get_smp_processor_id();
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
        schedule_event.tgid = tgid;
        // 提前将 count 值赋值为 1，避免输出时进程还没有被调度，导致除数出现 0 的情况
        schedule_event.count = 1;
        schedule_event.enter_time = current_time;

        bpf_map_update_elem(&enable_add,&pd,&e_add,BPF_ANY);
        bpf_map_update_elem(&proc_schedule,&pd,&schedule_event,BPF_ANY);
    }else{
        schedule_event->enter_time = current_time;
    }

    return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
    struct sched_ctrl *sched_ctrl;
	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
	if(!sched_ctrl || !sched_ctrl->sched_func)
		return 0;
    
    pid_t pid = BPF_CORE_READ(p,pid);
    int tgid = BPF_CORE_READ(p,tgid);
    int cpu = bpf_get_smp_processor_id();
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
        schedule_event.tgid = tgid;
        schedule_event.count = 1;
        schedule_event.enter_time = current_time;

        bpf_map_update_elem(&enable_add,&pd,&e_add,BPF_ANY);
        bpf_map_update_elem(&proc_schedule,&pd,&schedule_event,BPF_ANY);
    }else{
        schedule_event->enter_time = current_time;
    }

    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    struct sched_ctrl *sched_ctrl;
	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
	if(!sched_ctrl || !sched_ctrl->sched_func)
		return 0;
    
    pid_t prev_pid = BPF_CORE_READ(prev,pid);
    int prev_tgid = BPF_CORE_READ(prev,tgid);
    int prev_cpu = bpf_get_smp_processor_id();
    unsigned int prev_state = BPF_CORE_READ(prev,__state);
    pid_t next_pid = BPF_CORE_READ(next,pid);
    int next_tgid = BPF_CORE_READ(next,tgid);
    int next_cpu = prev_cpu;
    u64 current_time = bpf_ktime_get_ns();
    struct schedule_event *schedule_event;
    bool * e_add;
    struct proc_id next_pd = {};
    u64 this_delay;
    int key = 0;
    struct schedule_event *target_event;
    struct sum_schedule * sum_schedule;
    
    /* 记录自愿让出CPU进程的调度延迟开始时间 */
    if(prev_state==TASK_RUNNING){
        struct proc_id prev_pd = {};

        prev_pd.pid = prev_pid;
        if(prev_pid == 0)    prev_pd.cpu_id = prev_cpu;
        schedule_event = bpf_map_lookup_elem(&proc_schedule,&prev_pd);
        if(!schedule_event){
            struct schedule_event schedule_event = {};
            bool e_add = false;
            
            schedule_event.pid = prev_pid;
            schedule_event.tgid = prev_tgid;
            schedule_event.count = 1;
            schedule_event.enter_time = current_time;

            bpf_map_update_elem(&enable_add,&prev_pd,&e_add,BPF_ANY);
            bpf_map_update_elem(&proc_schedule,&prev_pd,&schedule_event,BPF_ANY);
        }else{
            schedule_event->enter_time = current_time;
        }
    }

    /* 记录所有进程的调度信息 */
    next_pd.pid = next_pid;
    if(next_pid == 0)    next_pd.cpu_id = next_cpu;
    schedule_event = bpf_map_lookup_elem(&proc_schedule,&next_pd);
    if(!schedule_event)
        return 0;

    e_add = bpf_map_lookup_elem(&enable_add,&next_pd);
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
    
    /* 若指定 target 进程，则单独记录 target 进程的调度信息 */
    if(sched_ctrl->target_pid!=-1 && ((sched_ctrl->target_pid!=0 && next_pid==sched_ctrl->target_pid) || 
        (sched_ctrl->target_pid==0 && next_pid==sched_ctrl->target_pid && next_cpu==sched_ctrl->target_cpu_id))){
        bpf_map_update_elem(&target_schedule,&key,schedule_event,BPF_ANY);
    }

    /* 记录指定的线程组调度信息 */
    if(next_tgid == sched_ctrl->target_tgid){
        bpf_map_update_elem(&tg_schedule,&next_pid,schedule_event,BPF_ANY);
    }
    
    /* 记录系统的调度信息 */
    sum_schedule = bpf_map_lookup_elem(&sys_schedule,&key);
    if(!sum_schedule){
        struct sum_schedule sum_schedule = {};

        sum_schedule.sum_count ++;
        sum_schedule.sum_delay += this_delay;
        if(this_delay > sum_schedule.max_delay)
            sum_schedule.max_delay = this_delay;
        if(sum_schedule.min_delay==0 || this_delay<sum_schedule.min_delay)
            sum_schedule.min_delay = this_delay;
        bpf_map_update_elem(&sys_schedule,&key,&sum_schedule,BPF_ANY);
    }else{
        sum_schedule->sum_count ++;
        sum_schedule->sum_delay += this_delay;
        if(this_delay > sum_schedule->max_delay)
            sum_schedule->max_delay = this_delay;
        if(sum_schedule->min_delay==0 || this_delay<sum_schedule->min_delay)
            sum_schedule->min_delay = this_delay;
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void *ctx)
{
    struct sched_ctrl *sched_ctrl;
	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
	if(!sched_ctrl || !sched_ctrl->sched_func)
		return 0;
    
    struct task_struct *p = (struct task_struct *)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(p,pid);
    int tgid = BPF_CORE_READ(p,tgid);
    int cpu = bpf_get_smp_processor_id();
    struct proc_id pd = {};
    struct schedule_event *schedule_event;
    bool * e_add;
    int key = 0;

    pd.pid = pid;
    if(pid == 0)    pd.cpu_id = cpu;

    // 从哈希表中删除退出进程的数据，防止哈希表溢出
    schedule_event = bpf_map_lookup_elem(&proc_schedule,&pd);
    if(schedule_event){
        bpf_map_delete_elem(&proc_schedule,&pd);
    }
    e_add = bpf_map_lookup_elem(&enable_add,&pd);
    if(e_add){
        bpf_map_delete_elem(&enable_add,&pd);
    }

    // 若目标进程退出，删除 target_schedule map 中的数据
    if(sched_ctrl->target_pid!=-1 && ((sched_ctrl->target_pid!=0 && pid==sched_ctrl->target_pid) || 
        (sched_ctrl->target_pid==0 && pid==sched_ctrl->target_pid && cpu==sched_ctrl->target_cpu_id))){
        schedule_event = bpf_map_lookup_elem(&target_schedule,&key);
        if(schedule_event){
            // 将 count 设置成 0 即可实现目标进程退出标志
            schedule_event->count = 0;
        }
    }

    // 若目标进程中的线程退出，删除 tg_schedule map 中的数据
    if(tgid == sched_ctrl->target_tgid){
        bpf_map_delete_elem(&tg_schedule,&pid);
    }

    return 0;
}