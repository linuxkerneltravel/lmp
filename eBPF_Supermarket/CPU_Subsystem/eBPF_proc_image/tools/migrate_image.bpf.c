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
// author: albert_xuu@163.com 

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>		//包含了BPF 辅助函数
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "migrate_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct { 
	__uint(type, BPF_MAP_TYPE_HASH); 
	__uint(key_size, sizeof(pid_t));
	__uint(value_size, sizeof(struct migrate_event));
	__uint(max_entries, 128);
} migrate SEC(".maps");
struct { 
	__uint(type, BPF_MAP_TYPE_ARRAY); 
	__uint(key_size, sizeof(int)); 
	__uint(value_size, sizeof(int)); 
	__uint(max_entries, 16); 
} t SEC(".maps");

SEC("tracepoint/sched/sched_migrate_task")
int tracepoint_sched_migrate_task(struct trace_event_raw_sched_migrate_task *args){
    u64 time = bpf_ktime_get_ns();//当前转移时间点;
    pid_t pid = args->pid;
    struct migrate_event *migrate_event;
    migrate_event = bpf_map_lookup_elem(&migrate,&pid);
    if(!migrate_event){
        int key = 0,*count=bpf_map_lookup_elem(&t,&key);
        if(!count){
            int init = 1;
            bpf_map_update_elem(&t,&key,&init,BPF_ANY);
        }
        else *count +=1;

        struct migrate_event migrate_event = {};
        migrate_event.pid = pid;
        migrate_event.prio = args->prio;
        migrate_event.migrate_info[0].time = time;
        migrate_event.migrate_info[0].orig_cpu = args->orig_cpu;
        migrate_event.migrate_info[0].dest_cpu = args->dest_cpu;
        migrate_event.count = 1;
        bpf_map_update_elem(&migrate, &pid, &migrate_event, BPF_ANY);
    }
    /*&& (migrate_event->migrate_info + migrate_event->count) < (migrate_event->migrate_info + MAX_MIGRATE)*/
    else if(migrate_event->count>0 && migrate_event->count<MAX_MIGRATE
            && (migrate_event->migrate_info + migrate_event->count) < (migrate_event->migrate_info + MAX_MIGRATE)  )
    {
        migrate_event->migrate_info[migrate_event->count].time = time;
        migrate_event->migrate_info[migrate_event->count].orig_cpu = args->orig_cpu;
        migrate_event->migrate_info[migrate_event->count++].dest_cpu = args->dest_cpu;
    } 
    else if(migrate_event->count>=MAX_MIGRATE)
    {   
        migrate_event->migrate_info[migrate_event->count % MAX_MIGRATE].time = time;
        migrate_event->migrate_info[migrate_event->count % MAX_MIGRATE].orig_cpu = args->orig_cpu;
        migrate_event->migrate_info[migrate_event->count % MAX_MIGRATE].dest_cpu = args->dest_cpu;
        migrate_event->count++;
        migrate_event->rear ++;
    }   

    //bpf_printk("Time:%llu\tpid:%d\tcomm:%s\tprio:%d\torig_cpu:%d\tdest_cpu:%d\t\n",time,args->pid,args->comm,args->prio,args->orig_cpu,args->dest_cpu);
    return 0;
}