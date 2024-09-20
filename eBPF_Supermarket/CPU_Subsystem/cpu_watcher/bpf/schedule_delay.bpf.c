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

const int ctrl_key = 0;
BPF_HASH(has_scheduled,struct proc_id, bool, 10240);//记录该进程是否调度过
BPF_HASH(enter_schedule,struct proc_id, struct schedule_event, 10240);//记录该进程上运行队列的时间
BPF_ARRAY(sys_schedule,int,struct sum_schedule,1);//记录整个系统的调度延迟
BPF_ARRAY(threshold_schedule,int,struct proc_schedule,10240);//记录每个进程的调度延迟
BPF_HASH(proc_histories,struct proc_id, struct proc_history, 10240);//记录每个进程运行前的两个进程
BPF_ARRAY(schedule_ctrl_map,int,struct schedule_ctrl,1);

static inline struct schedule_ctrl *get_schedule_ctrl(void) {
    struct schedule_ctrl *sched_ctrl;
    sched_ctrl = bpf_map_lookup_elem(&schedule_ctrl_map, &ctrl_key);
    if (!sched_ctrl || !sched_ctrl->schedule_func) {
        return NULL;
    }
    return sched_ctrl;
}//查找控制结构体

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p) {
    struct schedule_ctrl *sched_ctrl = get_schedule_ctrl();
    if (!sched_ctrl) {
        return 0;
    }
    pid_t pid = p->pid;
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
   struct schedule_ctrl *sched_ctrl = get_schedule_ctrl();
   if (!sched_ctrl) {
        return 0;
    }
	sched_ctrl = bpf_map_lookup_elem(&schedule_ctrl_map,&ctrl_key);
	if(!sched_ctrl || !sched_ctrl->schedule_func)
		return 0;
    pid_t pid = p->pid;
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
    struct schedule_ctrl *sched_ctrl = get_schedule_ctrl();
    if (!sched_ctrl) {
        return 0;
    }
    struct proc_history *history;
    struct proc_history new_history;
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
    struct proc_id next_id = {};
    u64 delay;
    if (prev_state == TASK_RUNNING) {
        struct proc_id prev_pd = {};
        prev_pd.pid = prev_pid;
        if (prev_pid == 0) {
            prev_pd.cpu_id = prev_cpu;
        }
        schedule_event = bpf_map_lookup_elem(&enter_schedule, &prev_pd);
        if (!schedule_event) {
            struct schedule_event schedule_event2;
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
    if (!schedule_event) return 0;
    issched = bpf_map_lookup_elem(&has_scheduled, &next_id);
    if (!issched) return 0;
    if (*issched) {
        schedule_event->count++;
    } else {
        *issched = true;
    }
    delay = current_time - schedule_event->enter_time;
    struct proc_schedule proc_schedule;
    proc_schedule.delay = delay;
    proc_schedule.id= next_id;
    bpf_probe_read_kernel_str(&proc_schedule.proc_name, sizeof(proc_schedule.proc_name), next->comm);
    bpf_map_update_elem(&threshold_schedule, &key, &proc_schedule, BPF_ANY);
    sum_schedule = bpf_map_lookup_elem(&sys_schedule, &key);
    if (!sum_schedule) {
        struct sum_schedule sum_schedule = {};
        sum_schedule.sum_count++;
        sum_schedule.sum_delay += delay;
        if (delay > sum_schedule.max_delay) {
            sum_schedule.max_delay = delay;
            if (next->pid != 0) {
                bpf_probe_read_kernel_str(&sum_schedule.proc_name_max, sizeof(sum_schedule.proc_name_max), next->comm);
            }
        } else if (sum_schedule.min_delay == 0 || delay < sum_schedule.min_delay) {
            sum_schedule.min_delay = delay;
            if (next->pid != 0) {
                bpf_probe_read_kernel_str(&sum_schedule.proc_name_min, sizeof(sum_schedule.proc_name_min), next->comm);
            }
        }
        bpf_map_update_elem(&sys_schedule, &key, &sum_schedule, BPF_ANY);
    } else {
        sum_schedule->sum_count++;
        sum_schedule->sum_delay += delay;
        if (delay > sum_schedule->max_delay) {
            sum_schedule->max_delay = delay;
            bpf_probe_read_kernel_str(&sum_schedule->proc_name_max, sizeof(sum_schedule->proc_name_max), next->comm);
        } else if (sum_schedule->min_delay == 0 || delay < sum_schedule->min_delay) {
            sum_schedule->min_delay = delay;
            if (next->pid != 0) {
                bpf_probe_read_kernel_str(&sum_schedule->proc_name_min, sizeof(sum_schedule->proc_name_min), next->comm);
            }
        }
    }
    history = bpf_map_lookup_elem(&proc_histories, &next_id);
    if (history) {
        // 如果找到了，更新历史记录
        new_history.last[0] = history->last[1];
        new_history.last[1].pid = prev->pid;
        bpf_probe_read_kernel_str(&new_history.last[1].comm, sizeof(new_history.last[1].comm), prev->comm);
        bpf_map_update_elem(&proc_histories, &next_id, &new_history, BPF_ANY);
    } else {
        // 如果没有找到，初始化新的历史记录
        new_history.last[0].pid = 0;  // 初始化为0，表示没有历史信息
        new_history.last[0].comm[0] = '\0';
        new_history.last[1].pid = prev->pid;
        bpf_probe_read_kernel_str(&new_history.last[1].comm, sizeof(new_history.last[1].comm), prev->comm);
        bpf_map_update_elem(&proc_histories, &next_id, &new_history, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void *ctx) {
    struct schedule_ctrl *sched_ctrl = get_schedule_ctrl();
    if (!sched_ctrl) {
        return 0;
    }
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