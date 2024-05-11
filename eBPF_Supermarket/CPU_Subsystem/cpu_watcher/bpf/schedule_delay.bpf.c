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
#define TASK_RUNNING			0x0000

BPF_HASH(has_scheduled,struct proc_id, bool, 10240);
BPF_HASH(enter_schedule,struct proc_id, struct schedule_event, 10240);
BPF_ARRAY(sys_schedule,int,struct sum_schedule,1);


SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p) {
    pid_t pid = BPF_CORE_READ(p, pid);
    int cpu = bpf_get_smp_processor_id();
    struct schedule_event *schedule_event;
    struct proc_id id= {};
    u64 current_time = bpf_ktime_get_ns();
    id.pid = pid;
    if (pid == 0) {
        id.cpu_id = cpu;
    }   
    schedule_event = bpf_map_lookup_elem(&enter_schedule, &id);
    if (!schedule_event) {
        struct schedule_event schedule_event1;
        bool issched = false;    
        schedule_event1.pid = pid;
        schedule_event1.count = 1;
        schedule_event1.enter_time = current_time;
        bpf_map_update_elem(&has_scheduled, &id, &issched, BPF_ANY);
        bpf_map_update_elem(&enter_schedule, &id, &schedule_event1, BPF_ANY);
    } else {
        schedule_event->enter_time = current_time;
    }
    return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p) {
    pid_t pid = BPF_CORE_READ(p, pid);
    int cpu = bpf_get_smp_processor_id();
    struct proc_id id= {};
    u64 current_time = bpf_ktime_get_ns();
    id.pid = pid;
    if (pid == 0) {
        id.cpu_id = cpu;
    }    
    struct schedule_event schedule_event;
    bool issched = false;    
    schedule_event.pid = pid;
    schedule_event.count = 1;
    schedule_event.enter_time = current_time;
    bpf_map_update_elem(&has_scheduled, &id, &issched, BPF_ANY);
    bpf_map_update_elem(&enter_schedule, &id, &schedule_event, BPF_ANY);
    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next) {
    u64 current_time = bpf_ktime_get_ns();
    pid_t prev_pid = prev->pid;
    unsigned int prev_state = prev->__state;
    int prev_cpu = bpf_get_smp_processor_id();
    pid_t next_pid = next->pid;
    int next_cpu = bpf_get_smp_processor_id();
    bool *issched;
    struct schedule_event *schedule_event;
    struct sum_schedule *sum_schedule;
    int key = 0;
    struct proc_id next_id= {};
    u64 delay;
    if (prev_state == TASK_RUNNING) {
        struct proc_id prev_pd= {};
        prev_pd.pid = prev_pid;
        if (prev_pid == 0) {
            prev_pd.cpu_id = prev_cpu;
        }    
        schedule_event = bpf_map_lookup_elem(&enter_schedule, &prev_pd);
        if (!schedule_event) {
            struct schedule_event schedule_event2 ;
            bool issched = false;
            schedule_event2.pid = prev_pid;
            schedule_event2.count = 1;
            schedule_event2.enter_time = current_time;
            bpf_map_update_elem(&has_scheduled, &prev_pd, &issched, BPF_ANY);
            bpf_map_update_elem(&enter_schedule, &prev_pd, &schedule_event2, BPF_ANY);
        } else {
            schedule_event->enter_time = current_time;
        }
    }

    next_id.pid = next_pid;
    if (next_pid == 0) {
        next_id.cpu_id = next_cpu;
    }
    schedule_event = bpf_map_lookup_elem(&enter_schedule, &next_id);
    if (!schedule_event)  return 0;
    issched = bpf_map_lookup_elem(&has_scheduled, &next_id);
    if (!issched)  return 0;   
    if (*issched) {
        schedule_event->count++;
    } else {
        *issched = true;
    }   
    delay = current_time - schedule_event->enter_time;
    sum_schedule = bpf_map_lookup_elem(&sys_schedule, &key);
    if (!sum_schedule) {
        struct sum_schedule sum_schedule= {};
        sum_schedule.sum_count++;
        sum_schedule.sum_delay += delay;
        if (delay > sum_schedule.max_delay){
            sum_schedule.max_delay = delay;
            if(next->pid!=0){
                sum_schedule.pid_max = next->pid;
            }
        }else if (sum_schedule.min_delay == 0 || delay < sum_schedule.min_delay)
            sum_schedule.min_delay = delay;
            if(next->pid!=0){
                sum_schedule.pid_min = next->pid;
            }
        bpf_map_update_elem(&sys_schedule, &key, &sum_schedule, BPF_ANY);
    } else {
        sum_schedule->sum_count++;
        sum_schedule->sum_delay += delay;
        if (delay > sum_schedule->max_delay){
            sum_schedule->max_delay = delay;
            if(next->pid!=0){
                sum_schedule->pid_max = next->pid;
            }
        }else if (sum_schedule->min_delay == 0 || delay < sum_schedule->min_delay)
            sum_schedule->min_delay = delay;
            if(next->pid!=0){
                sum_schedule->pid_min = next->pid;
            }
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void *ctx) {
    struct task_struct *p = (struct task_struct *)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(p, pid);
    int cpu = bpf_get_smp_processor_id();
    struct proc_id id= {};
    struct schedule_event *schedule_event;
    bool *issched;
    int key = 0;
    id.pid = pid;
    if (pid == 0)    id.cpu_id = cpu;
    schedule_event = bpf_map_lookup_elem(&enter_schedule, &id);
    if (schedule_event) {
        bpf_map_delete_elem(&enter_schedule, &id);
    }
    issched = bpf_map_lookup_elem(&has_scheduled, &id);
    if (issched) {
        bpf_map_delete_elem(&has_scheduled, &id);
    }
    return 0;
}
