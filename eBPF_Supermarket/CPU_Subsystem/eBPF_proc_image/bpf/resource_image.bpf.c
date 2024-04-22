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
// eBPF kernel-mode code that collects process resource usage

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/version.h>
#include "proc_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t ignore_tgid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct rsc_ctrl);
} rsc_ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct proc_id);
	__type(value, struct start_rsc);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct proc_id);
	__type(value, struct total_rsc);
} total SEC(".maps");

SEC("kprobe/finish_task_switch.isra.0")
int kprobe__finish_task_switch(struct pt_regs *ctx)
{
	int key = 0;
	struct rsc_ctrl *rsc_ctrl;
	rsc_ctrl = bpf_map_lookup_elem(&rsc_ctrl_map,&key);
	if(!rsc_ctrl || !rsc_ctrl->rsc_func)
		return 0;

	struct task_struct *prev = (struct task_struct *)PT_REGS_PARM1(ctx);
	pid_t prev_pid = BPF_CORE_READ(prev,pid);
	int prev_cpu = bpf_get_smp_processor_id();
	int prev_tgid = BPF_CORE_READ(prev,tgid);
	struct task_struct *next = (struct task_struct *)bpf_get_current_task();
	pid_t next_pid = BPF_CORE_READ(next,pid);
	int next_cpu = prev_cpu;
	int next_tgid = BPF_CORE_READ(next,tgid);
	
	if((rsc_ctrl->enable_myproc || prev_tgid!=ignore_tgid) && ((rsc_ctrl->target_pid==-1 && rsc_ctrl->target_tgid==-1) || (rsc_ctrl->target_pid!=0 && prev_pid==rsc_ctrl->target_pid) || 
	   (rsc_ctrl->target_pid==0 && prev_pid==rsc_ctrl->target_pid && prev_cpu==rsc_ctrl->target_cpu_id) || (prev_tgid==rsc_ctrl->target_tgid))){
		struct proc_id prev_pd = {};
		prev_pd.pid = prev_pid;
		if(prev_pid == 0)	prev_pd.cpu_id = prev_cpu;
		
		if(bpf_map_lookup_elem(&start,&prev_pd) != NULL){
			struct start_rsc *prev_start = bpf_map_lookup_elem(&start,&prev_pd);
			if (prev_start == NULL) {
				return 0; 
			}
			
			if(bpf_map_lookup_elem(&total,&prev_pd) == NULL){
				struct total_rsc prev_total = {};
				long unsigned int memused;
				
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
				struct percpu_counter *rss;
				rss = BPF_CORE_READ(prev,mm,rss_stat);
				if(!rss)	return 0;
				memused = rss[0].count + rss[1].count + rss[3].count;
/* #else
				struct mm_rss_stat rss = {};
				long long *c;
				rss = BPF_CORE_READ(prev, mm, rss_stat);
				c = (long long *)(rss.count);
				if(!c)	return 0;
				memused = *c + *(c + 1) + *(c + 3);
#endif */
				
				prev_total.pid = prev_pd.pid;
				if(rsc_ctrl->target_tgid != -1)	prev_total.tgid = prev_tgid;
				else	prev_total.tgid = -1;
				prev_total.cpu_id = prev_cpu;
				prev_total.time = bpf_ktime_get_ns() - prev_start->time;
				prev_total.memused = memused;
				prev_total.readchar = BPF_CORE_READ(prev,ioac.rchar) - prev_start->readchar;
				prev_total.writechar = BPF_CORE_READ(prev,ioac.wchar) - prev_start->writechar;
				
				bpf_map_update_elem(&total,&prev_pd, &prev_total, BPF_ANY);
			}else{
				struct total_rsc *prev_total = bpf_map_lookup_elem(&total,&prev_pd);
				if (prev_total == NULL) {
					return 0; 
				}
				
				long unsigned int memused;
				
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
				struct percpu_counter *rss;
				rss = BPF_CORE_READ(prev,mm,rss_stat);
				if(!rss)	return 0;
				memused = rss[0].count + rss[1].count + rss[3].count;
/* #else
				struct mm_rss_stat rss = {};
				long long *c;
				rss = BPF_CORE_READ(prev, mm, rss_stat);
				c = (long long *)(rss.count);
				if(!c)	return 0;
				memused = *c + *(c + 1) + *(c + 3);
#endif */
				
				prev_total->cpu_id = prev_cpu;
				prev_total->time += bpf_ktime_get_ns() - prev_start->time;
				prev_total->memused = memused;
				prev_total->readchar += BPF_CORE_READ(prev,ioac.rchar) - prev_start->readchar;
				prev_total->writechar += BPF_CORE_READ(prev,ioac.wchar) - prev_start->writechar;
				
				bpf_map_update_elem(&total,&prev_pd, &(*prev_total), BPF_ANY);
			}
		}
	}
	
	if((rsc_ctrl->enable_myproc || next_tgid!=ignore_tgid) && ((rsc_ctrl->target_pid==-1 && rsc_ctrl->target_tgid==-1) || (rsc_ctrl->target_pid!=0 && next_pid==rsc_ctrl->target_pid) || 
	   (rsc_ctrl->target_pid==0 && next_pid==rsc_ctrl->target_pid && next_cpu==rsc_ctrl->target_cpu_id) || (next_tgid==rsc_ctrl->target_tgid))){
		struct proc_id next_pd = {};
		struct start_rsc next_start={};

		next_pd.pid = next_pid;
		if(next_pid == 0)	next_pd.cpu_id = next_cpu;
		
		next_start.time = bpf_ktime_get_ns();
		next_start.readchar = BPF_CORE_READ(next,ioac.rchar);
		next_start.writechar = BPF_CORE_READ(next,ioac.wchar);
		
		bpf_map_update_elem(&start,&next_pd, &next_start, BPF_ANY);
	}

	return 0;
}
