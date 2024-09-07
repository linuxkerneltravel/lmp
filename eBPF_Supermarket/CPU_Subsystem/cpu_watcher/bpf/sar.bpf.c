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

const volatile long long unsigned int forks_addr = 0;
const int ctrl_key = 0;
#define PF_IDLE			0x00000002	/* I am an IDLE thread */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */

// 计数表格，第0项为所统计fork数，第1项为进程切换数
BPF_ARRAY(countMap,int,u64,3);
// 记录开始的时间
BPF_ARRAY(procStartTime,pid_t,u64,4096);
//存储运行队列长度
BPF_ARRAY(runqlen,u32,int,1);
//记录软中断开始时间
BPF_HASH(softirqCpuEnterTime,u32,u64,4096);
//记录软中断结束时间
BPF_HASH(softirqLastTime,u32,u64,1);
// 记录开始的时间
BPF_HASH(irq_cpu_enter_start,u32,u64,8192);
//记录上次中断时间
BPF_ARRAY(irq_Last_time,u32,u64,1);
// 储存cpu进入空闲的起始时间
BPF_ARRAY(idleStart,u32,u64,128);
// 储存cpu进入空闲的持续时间
BPF_ARRAY(idleLastTime,u32,u64,1);
// 储存cpu运行内核线程的时间
BPF_ARRAY(kt_LastTime,u32,u64,1);
// 储存cpu运行用户线程的时间
BPF_ARRAY(ut_LastTime,u32,u64,1);
BPF_ARRAY(tick_user,u32,u64,1);
BPF_ARRAY(symAddr,u32,u64,1);
BPF_ARRAY(sar_ctrl_map,int,struct sar_ctrl,1);

static inline struct sar_ctrl *get_sar_ctrl(void) {
    struct sar_ctrl *sar_ctrl;
    sar_ctrl = bpf_map_lookup_elem(&sar_ctrl_map, &ctrl_key);
    if (!sar_ctrl || !sar_ctrl->sar_func) {
        return NULL;
    }
    return sar_ctrl;
}

// 统计fork数
SEC("kprobe/finish_task_switch.isra.0")
// SEC("kprobe/finish_task_switch")
int kprobe__finish_task_switch(struct pt_regs *ctx)
{
	struct sar_ctrl *sar_ctrl = get_sar_ctrl();
	if (!sar_ctrl) {
        return 0;
    }
    u32 key = 0;
    u64 val, *valp = NULL;
    unsigned long total_forks;
     
    if(forks_addr !=0){
        valp = (u64 *)forks_addr;
        bpf_probe_read_kernel(&total_forks, sizeof(unsigned long), valp);
        key = 1;
        val = total_forks;
        bpf_map_update_elem(&countMap,&key,&val,BPF_ANY);
    }
    return 0;
}

//获取进程切换数;
SEC("tracepoint/sched/sched_switch")
int trace_sched_switch2(struct cswch_args *info) {
	struct sar_ctrl *sar_ctrl = get_sar_ctrl();
	if (!sar_ctrl) {
        return 0;
    }
	pid_t prev = info->prev_pid, next = info->next_pid;
	if (prev != next) {
		u32 key = 0;
		u64 *valp, delta, cur;
		struct task_struct *ts;
		pid_t pid = next;
		u64 time = bpf_ktime_get_ns();
		bpf_map_update_elem(&procStartTime,&pid,&time,BPF_ANY);
		valp =  bpf_map_lookup_elem(&countMap,&key);
		if (!valp) {
			u64 initval = 1;
			bpf_map_update_elem(&countMap,&key,&initval,BPF_ANY);
		}
		else *valp += 1;
	}
	return 0;
}

// SEC("kprobe/finish_task_switch")
SEC("kprobe/finish_task_switch.isra.0")
int BPF_KPROBE(finish_task_switch,struct task_struct *prev){
	struct sar_ctrl *sar_ctrl = get_sar_ctrl();
	if (!sar_ctrl) {
        return 0;
    }
	pid_t pid=BPF_CORE_READ(prev,pid);
	u64 *val, time = bpf_ktime_get_ns();
	u64 delta;
	// 记录内核进程（非IDLE）运行时间
	if ((BPF_CORE_READ(prev,flags) & PF_KTHREAD) && pid!= 0) {
		val = bpf_map_lookup_elem(&procStartTime, &pid);
		if (val) {
			u32 key = 0;
			delta = time - *val;
			val = bpf_map_lookup_elem(&kt_LastTime, &key);
			if (val) *val += delta;
			else bpf_map_update_elem(&kt_LastTime, &key, &delta, BPF_ANY);
		}// 记录用户进程的运行时间
	}else if (!(BPF_CORE_READ(prev,flags) & PF_KTHREAD) && !(BPF_CORE_READ(prev,flags) &PF_IDLE)) {
		val = bpf_map_lookup_elem(&procStartTime, &pid);
		if (val) {
		u32 key = 0;
 		delta = (time - *val);
 		val = bpf_map_lookup_elem(&ut_LastTime, &key);
		if (val) *val += delta;
 		else bpf_map_update_elem(&ut_LastTime, &key, &delta, BPF_ANY);
		}
	} 
	return 0;

}

//统计运行队列长度
SEC("kprobe/update_rq_clock")
int BPF_KPROBE(update_rq_clock,struct rq *rq){
	struct sar_ctrl *sar_ctrl = get_sar_ctrl();
	if (!sar_ctrl) {
        return 0;
    }
    u32 key = 0;
    u64 val = BPF_CORE_READ(rq,nr_running);
    bpf_map_update_elem(&runqlen,&key,&val,BPF_ANY);
    return 0;
}

//软中断
SEC("tracepoint/irq/softirq_entry")
int trace_softirq_entry(struct __softirq_info *info) {
	struct sar_ctrl *sar_ctrl = get_sar_ctrl();
	if (!sar_ctrl) {
        return 0;
    }
	u32 key = info->vec;
	u64 val = bpf_ktime_get_ns();
	bpf_map_update_elem(&softirqCpuEnterTime, &key, &val, BPF_ANY);
	return 0;
}

SEC("tracepoint/irq/softirq_exit")
int trace_softirq_exit(struct __softirq_info *info) {
	struct sar_ctrl *sar_ctrl = get_sar_ctrl();
	if (!sar_ctrl) {
        return 0;
    }
	u32 key = info->vec;
	u64 now = bpf_ktime_get_ns(), *valp = 0;
	valp =bpf_map_lookup_elem(&softirqCpuEnterTime, &key);
	if (valp) {
		// 找到表项
		u64 last_time = now - *valp;
		u32 key0 = 0;
		valp = bpf_map_lookup_elem(&softirqLastTime, &key0);
		if (!valp) bpf_map_update_elem(&softirqLastTime, &key0, &last_time, BPF_ANY);
		else *valp += last_time;
	}	
	return 0;
}

/*irqtime：CPU响应irq中断所占用的时间。
注意这是所有CPU时间的叠加，平均到每个CPU应该除以CPU个数。*/
SEC("tracepoint/irq/irq_handler_entry")
int trace_irq_handler_entry(struct __irq_info *info) {
	struct sar_ctrl *sar_ctrl = get_sar_ctrl();
	if (!sar_ctrl) {
        return 0;
    }
	u32 key = info->irq;
	u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&irq_cpu_enter_start, &key, &ts, BPF_ANY);
	return 0;
}

SEC("tracepoint/irq/irq_handler_exit")
int trace_irq_handler_exit(struct __irq_info *info) {
	struct sar_ctrl *sar_ctrl = get_sar_ctrl();
	if (!sar_ctrl) {
        return 0;
    }
	u32 key = info->irq;
	u64 now = bpf_ktime_get_ns(), *ts = 0;
    ts = bpf_map_lookup_elem(&irq_cpu_enter_start, &key);
	if (ts) {
        u64 last_time = now - *ts;
	    u32 key0 = 0;
		ts = bpf_map_lookup_elem(&irq_Last_time, &key0);
		if (!ts)   
			 bpf_map_update_elem(&irq_Last_time, &key0, &last_time, BPF_ANY);
		else        
			*ts += last_time;
	}
	return 0;
}


//tracepoint:power_cpu_idle 表征了CPU进入IDLE的状态，比较准确
SEC("tracepoint/power/cpu_idle")
int trace_cpu_idle(struct idleStruct *pIDLE) {
	struct sar_ctrl *sar_ctrl = get_sar_ctrl();
	if (!sar_ctrl) {
        return 0;
    }
	u64 delta, time = bpf_ktime_get_ns();
	u32 key = pIDLE->cpu_id;
	if (pIDLE->state == -1) {
		u64 *valp = bpf_map_lookup_elem(&idleStart,&key);
		if (valp && *valp != 0) {
			delta = time - *valp;
			key = 0;
			valp = bpf_map_lookup_elem(&idleLastTime,&key);
			if (valp) *valp += delta;
			else bpf_map_update_elem(&idleLastTime,&key,&delta,BPF_ANY);//初次记录持续空闲时间;
		}
	} else {
		u64 val = time;
		bpf_map_update_elem(&idleStart,&key,&time,BPF_ANY);
	}
	return 0;
}

static __always_inline int user_mode(struct pt_regs *regs)
{
	#ifdef CONFIG_X86_32
		return ((regs->cs & SEGMENT_RPL_MASK) | (regs->flags & X86_VM_MASK)) >= USER_RPL;
	#else
		return !!(regs->cs & 3);
	#endif
}
// 两个CPU各自会产生一个调用，这正好方便我们使用
SEC("perf_event")
int tick_update(struct pt_regs *ctx) {
	struct sar_ctrl *sar_ctrl = get_sar_ctrl();
	if (!sar_ctrl) {
        return 0;
    }

	// bpf_trace_printk("cs_rpl = %x\n", ctx->cs & 3);
	u32 key = 0;
	u64 val, *valp;

	// 记录用户态时间，直接从头文件arch/x86/include/asm/ptrace.h中引用
	if (user_mode(ctx)) {
		u64 initval = 1;
		valp = bpf_map_lookup_elem(&tick_user, &key);
		if (valp) *valp += 1;
		else bpf_map_update_elem(&tick_user, &key, &initval, BPF_ANY);
	}

	unsigned long total_forks;

	// if(forks_addr !=0){
    //     valp = (u64 *)forks_addr;
    //     bpf_probe_read_kernel(&total_forks, sizeof(unsigned long), valp);
    //     key = 1;
    //     val = total_forks;
    //     bpf_map_update_elem(&countMap,&key,&val,BPF_ANY);
    // }

	valp = bpf_map_lookup_elem(&symAddr, &key);
	if (valp) {
		void *addr = (void *)(*valp);
		if (addr > 0) {
			bpf_probe_read_kernel(&total_forks, sizeof(unsigned long), addr);
			key = 1;
			val = total_forks;
			bpf_map_update_elem(&countMap, &key, &val, BPF_ANY);
		}
	}

	return 0;
}
