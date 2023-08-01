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
const volatile int target_cpu_id = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct proc_id);
	__type(value, struct proc_oncpu);
} oncpu SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct proc_id);
	__type(value, struct proc_offcpu);
} offcpu SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 1024);
} cpu_rb SEC(".maps");

SEC("kprobe/finish_task_switch.isra.0")
int kprobe__finish_task_switch(struct pt_regs *ctx)
{
    struct task_struct *next = (struct task_struct *)bpf_get_current_task();
	struct task_struct *prev = (struct task_struct *)PT_REGS_PARM1(ctx);
    pid_t next_pid = BPF_CORE_READ(next,pid);
	pid_t prev_pid = BPF_CORE_READ(prev,pid);
	int cpu_id = bpf_get_smp_processor_id();

	// 第一种情况：目标进程从offcpu转变为oncpu
	if((target_pid!= 0 && prev_pid!= target_pid && next_pid==target_pid) || 
		(target_pid==0 && prev_pid!= target_pid && next_pid==target_pid && cpu_id==target_cpu_id))
	{
		u64 oncpu_time = bpf_ktime_get_ns();
		struct proc_id proc_id = {};
		struct proc_offcpu * proc_offcpu;

		proc_id.pid = target_pid;
		proc_id.cpu_id = target_cpu_id;

		proc_offcpu = bpf_map_lookup_elem(&offcpu, &proc_id);
		if(proc_offcpu){
			// 完成一次cpu_event(offcpu)的输出
			struct cpu_event *cpu_event;
			cpu_event = bpf_ringbuf_reserve(&cpu_rb, sizeof(*cpu_event), 0);
			if(!cpu_event){
				return 0;
			}

			cpu_event->pid = target_pid;
			cpu_event->flag = 0;
			bpf_get_current_comm(&cpu_event->comm, sizeof(cpu_event->comm));
			cpu_event->oncpu_id = cpu_id;
			cpu_event->oncpu_time = oncpu_time;
			cpu_event->offcpu_id = proc_offcpu->offcpu_id;
			cpu_event->offcpu_time = proc_offcpu->offcpu_time;

			bpf_ringbuf_submit(cpu_event, 0);

			bpf_map_delete_elem(&offcpu, &proc_id);
		}

		// 记录pro_oncpu
		struct proc_oncpu proc_oncpu ={};

		proc_oncpu.oncpu_id = cpu_id;
		proc_oncpu.oncpu_time = oncpu_time;

		if(bpf_map_update_elem(&oncpu, &proc_id, &proc_oncpu, BPF_ANY))
			return 0;

	// 第二中情况：目标进程从oncpu转变为offcpu
	}else if((target_pid!= 0 && prev_pid==target_pid && next_pid!=target_pid) || 
		(target_pid==0 && prev_pid==target_pid && next_pid!=target_pid && cpu_id==target_cpu_id))
	{
		u64 offcpu_time = bpf_ktime_get_ns();
		struct proc_id proc_id = {};
		struct proc_oncpu * proc_oncpu;

		proc_id.pid = target_pid;
		proc_id.cpu_id = target_cpu_id;

		proc_oncpu = bpf_map_lookup_elem(&oncpu, &proc_id);
		if(proc_oncpu){
			// 完成一次cpu_event(oncpu)的输出
			struct cpu_event *cpu_event;
			cpu_event = bpf_ringbuf_reserve(&cpu_rb, sizeof(*cpu_event), 0);
			if(!cpu_event){
				return 0;
			}
			
			// cpu_event->comm应该写入prev进程的comm
			for(int i = 0; i <= TASK_COMM_LEN - 1; i++){
				cpu_event->comm[i] = BPF_CORE_READ(prev,comm[i]);
				if (BPF_CORE_READ(prev,comm[i]) == '\0')
					break;
			}

			cpu_event->pid = target_pid;
			cpu_event->flag = 1;
			cpu_event->oncpu_id = proc_oncpu->oncpu_id;
			cpu_event->oncpu_time = proc_oncpu->oncpu_time;
			cpu_event->offcpu_id = cpu_id;
			cpu_event->offcpu_time = offcpu_time;

			bpf_ringbuf_submit(cpu_event, 0);

			bpf_map_delete_elem(&oncpu, &proc_id);
		}

		// 记录pro_offcpu
		struct proc_oncpu proc_offcpu ={};

		proc_offcpu.oncpu_id = cpu_id;
		proc_offcpu.oncpu_time = offcpu_time;

		if(bpf_map_update_elem(&offcpu, &proc_id, &proc_offcpu, BPF_ANY))
			return 0;

	// 第三种情况：目标进程被重新调度
	}else if((target_pid!= 0 && prev_pid==target_pid && next_pid==target_pid) || 
		(target_pid==0 && prev_pid==target_pid && next_pid==target_pid && cpu_id==target_cpu_id))
	{
		u64 offcpu_time = bpf_ktime_get_ns();
		struct proc_id proc_id = {};
		struct proc_oncpu * proc_oncpu;

		proc_id.pid = target_pid;
		proc_id.cpu_id = target_cpu_id;

		proc_oncpu = bpf_map_lookup_elem(&oncpu, &proc_id);
		if(proc_oncpu){
			// 完成一次cpu_event(oncpu)的输出
			struct cpu_event *cpu_event;
			cpu_event = bpf_ringbuf_reserve(&cpu_rb, sizeof(*cpu_event), 0);
			if(!cpu_event){
				return 0;
			}
			
			// cpu_event->comm应该写入prev进程的comm
			for(int i = 0; i <= TASK_COMM_LEN - 1; i++){
				cpu_event->comm[i] = BPF_CORE_READ(prev,comm[i]);
				if (BPF_CORE_READ(prev,comm[i]) == '\0')
					break;
			}

			cpu_event->pid = target_pid;
			cpu_event->flag = 1;
			cpu_event->oncpu_id = proc_oncpu->oncpu_id;
			cpu_event->oncpu_time = proc_oncpu->oncpu_time;
			cpu_event->offcpu_id = cpu_id;
			cpu_event->offcpu_time = offcpu_time;

			bpf_ringbuf_submit(cpu_event, 0);

			bpf_map_delete_elem(&oncpu, &proc_id);
		}

		// 记录pro_oncpu
		struct proc_oncpu proc_re_oncpu ={};

		proc_re_oncpu.oncpu_id = cpu_id;
		proc_re_oncpu.oncpu_time = offcpu_time;

		if(bpf_map_update_elem(&oncpu, &proc_id, &proc_re_oncpu, BPF_ANY))
			return 0;
	}

	return 0;

}