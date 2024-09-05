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
	__uint(max_entries, 1024);
} migrate SEC(".maps");

struct { 
	__uint(type, BPF_MAP_TYPE_HASH); 
	__uint(key_size, sizeof(struct minfo_key));
	__uint(value_size, sizeof(struct per_migrate));
	__uint(max_entries, 1024);
} migrate_info SEC(".maps");

SEC("tracepoint/sched/sched_migrate_task")
int tracepoint_sched_migrate_task(struct trace_event_raw_sched_migrate_task *args){
    u64 time = bpf_ktime_get_ns();//当前转移时间点;
    pid_t pid = args->pid;
    struct migrate_event *migrate_event;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct rq *orig_rq = BPF_CORE_READ(task,se.cfs_rq,rq);
    struct cfs_rq *orig_cfs = BPF_CORE_READ(task,se.cfs_rq);

    bpf_printk("[se]:Pload_avg:%llu\tPutil_avg:%llu\n",BPF_CORE_READ(task,se.avg.load_avg),BPF_CORE_READ(task,se.avg.util_avg));
    bpf_printk("[rq]: nr_running :%d  cpu_capacity : %ld  cpu_capacity_orig : %ld\n",
                BPF_CORE_READ(orig_rq,cpu),BPF_CORE_READ(orig_rq,nr_running),
                BPF_CORE_READ(orig_rq,cpu_capacity),BPF_CORE_READ(orig_rq,cpu_capacity_orig));  
    bpf_printk("Cload_avg:%ld\n",BPF_CORE_READ(orig_cfs,avg.runnable_avg));
    migrate_event = bpf_map_lookup_elem(&migrate,&pid);
    if(!migrate_event){
        struct migrate_event migrate_event = {};
        struct per_migrate per_migrate = {};
        struct minfo_key mkey = {};
        mkey.pid = pid;
        mkey.count = 1;
        migrate_event.pid = pid;
        migrate_event.prio = args->prio;
        migrate_event.count = 1;
        migrate_event.rear = 1;
        per_migrate.time = time;
        per_migrate.orig_cpu = args->orig_cpu;
        per_migrate.dest_cpu = args->dest_cpu;

        per_migrate.cpu_capacity = BPF_CORE_READ(orig_rq,cpu_capacity);
        per_migrate.cpu_capacity_orig = BPF_CORE_READ(orig_rq,cpu_capacity_orig);
        per_migrate.cpu_load_avg = BPF_CORE_READ(orig_cfs,avg.runnable_avg);


        per_migrate.pload_avg = BPF_CORE_READ(task,se.avg.load_avg);//进程的量化负载；
        per_migrate.putil_avg = BPF_CORE_READ(task,se.avg.util_avg);//进程的实际算力；
        per_migrate.mem_usage = BPF_CORE_READ(task,mm,total_vm) << PAGE_SHIFT;


        per_migrate.read_bytes = BPF_CORE_READ(task,ioac.read_bytes);
        per_migrate.write_bytes = BPF_CORE_READ(task,ioac.write_bytes);

        per_migrate.context_switches =  BPF_CORE_READ(task,nvcsw) + BPF_CORE_READ(task,nivcsw);
        // per_migrate.runtime =  BPF_CORE_READ(task,se.sum_exec_runtime);
        bpf_map_update_elem(&migrate_info, &mkey, &per_migrate, BPF_ANY);
        bpf_map_update_elem(&migrate, &pid, &migrate_event, BPF_ANY);
    }
    /*&& (migrate_event->migrate_info + migrate_event->count) < (migrate_event->migrate_info + MAX_MIGRATE)*/
    else if(migrate_event->count>0 && migrate_event->count<MAX_MIGRATE)
    {
        struct per_migrate per_migrate = {};
        struct minfo_key mkey = {};
        migrate_event->count++;
        mkey.pid = pid;
        mkey.count =  migrate_event->count;  
        per_migrate.time = time;
        per_migrate.orig_cpu = args->orig_cpu;
        per_migrate.dest_cpu = args->dest_cpu;

        per_migrate.cpu_capacity = BPF_CORE_READ(orig_rq,cpu_capacity);
        per_migrate.cpu_capacity_orig = BPF_CORE_READ(orig_rq,cpu_capacity_orig);
        per_migrate.cpu_load_avg = BPF_CORE_READ(orig_cfs,avg.runnable_avg);

        per_migrate.pload_avg = BPF_CORE_READ(task,se.avg.load_avg);//进程的量化负载；
        per_migrate.putil_avg = BPF_CORE_READ(task,se.avg.util_avg);//进程的实际算力；
        per_migrate.mem_usage = BPF_CORE_READ(task,mm,total_vm) << PAGE_SHIFT;


        per_migrate.read_bytes = BPF_CORE_READ(task,ioac.read_bytes);
        per_migrate.write_bytes = BPF_CORE_READ(task,ioac.write_bytes);

        per_migrate.context_switches =  BPF_CORE_READ(task,nvcsw) + BPF_CORE_READ(task,nivcsw);
        // per_migrate.runtime =  BPF_CORE_READ(task,se.sum_exec_runtime);

        bpf_map_update_elem(&migrate_info, &mkey, &per_migrate, BPF_ANY);
    } 
    return 0;
}