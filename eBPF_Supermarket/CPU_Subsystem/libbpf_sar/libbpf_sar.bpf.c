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
// kernel-mode code for libbpf sar

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "libbpf_sar.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile long long unsigned int forks_addr = 0;

// 计数表格，第0项为所统计fork数，第1项为进程切换数,第2项为运行队列长度
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);//基于数组的映射
	__uint(max_entries, 3);//countMap 可以存储最多 3 对键值对
	__type(key, int);
	__type(value, u64);
} countMap SEC(".maps");

// 记录开始的时间
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, u64);
} start SEC(".maps");//记录时间戳；

//环形缓冲区；
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

//cswch_args结构体
struct cswch_args {
	u64 pad;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
};

// 储存运行队列rq的全局变量
struct {
__uint(type, BPF_MAP_TYPE_ARRAY);
__uint(max_entries, 1);
__type(key, u32);
__type(value, struct rq);
} rq_map SEC(".maps");


struct {
__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
__uint(max_entries, 1);
__type(key, u32);
__type(value, int);
} runqlen SEC(".maps");//多CPU数组

struct __softirq_info {
	u64 pad;
	u32 vec;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, u64);
} softirqCpuEnterTime SEC(".maps");//记录软中断开始时间

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} softirqLastTime SEC(".maps");//软中断结束时间

// 统计fork数
SEC("kprobe/finish_task_switch.isra.0")
int kprobe__finish_task_switch(struct pt_regs *ctx)
{
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
SEC("tracepoint/sched/sched_switch")//静态挂载点
int trace_sched_switch2(struct cswch_args *info) {
	//从参数info中获取上一个(prev)和下一个(next)进程的进程号
	pid_t prev = info->prev_pid, next = info->next_pid;//定义上一个、下一个进程的进程号
	
	// 只有当上一个进程和下一个进程不相同时才执行以下操作，相同则代表是同一个进程
	if (prev != next) {
		u32 key = 1;
		u64 *valp, delta, cur;
		struct task_struct *ts;

		// 将下一个进程的进程号赋给pid
		pid_t pid = next;
		u64 time = bpf_ktime_get_ns()/1000;//获取当前时间，ms；

		// Step1: 记录next进程的起始时间
		bpf_map_update_elem(&start,&pid,&time,BPF_ANY);//上传当前时间到start map中
		//procStartTime.update(&pid, &time);//python

		// Step2: Syscall时间处理
		// record_sysc(time, prev, next);

		// Step3: UserMode时间处理
		// record_user(time, prev, next);

		// Step4: 记录上下文切换的总次数
		valp =  bpf_map_lookup_elem(&countMap,&key);
		if (!valp) {
			// 没有找到表项
			u64 initval = 1;
			bpf_map_update_elem(&countMap,&key,&initval,BPF_ANY);//初始化切换次数到countMap中
		}
		else *valp += 1;
		//bpf_map_update_elem(&countMap,&key,&valp,BPF_ANY);//上传当前切换次数到countMap中
	}

	return 0;
}

/*
SEC("kprobe/finish_task_switch")//动态挂载点
int trace_sched_switch(struct cswch_args *info) {
	//从参数info中获取上一个(prev)和下一个(next)进程的进程号
	pid_t prev = info->prev_pid, next = info->next_pid;//定义上一个、下一个进程的进程号
	
	// 只有当上一个进程和下一个进程不相同时才执行以下操作，相同则代表是同一个进程
	if (prev != next) {
		u32 key = 2;
		u64 *valp, delta, cur;
		struct task_struct *ts;

		// 将下一个进程的进程号赋给pid
		pid_t pid = next;
		u64 time = bpf_ktime_get_ns()/1000;//获取当前时间，ms；

		// Step1: 记录next进程的起始时间
		bpf_map_update_elem(&start,&pid,&time,BPF_ANY);//上传当前时间到start map中
		//procStartTime.update(&pid, &time);//python

		// Step2: Syscall时间处理
		// record_sysc(time, prev, next);

		// Step3: UserMode时间处理
		// record_user(time, prev, next);

		// Step4: 记录上下文切换的总次数
		valp =  bpf_map_lookup_elem(&countMap,&key);
		if (!valp) {
			// 没有找到表项
			u64 initval = 1;
			bpf_map_update_elem(&countMap,&key,&initval,BPF_ANY);//初始化切换次数到countMap中
		}
		else *valp += 1;
		//bpf_map_update_elem(&countMap,&key,&valp,BPF_ANY);//上传当前切换次数到countMap中
	}

	return 0;
}
*/


//统计运行队列长度
SEC("kprobe/update_rq_clock")
int kprobe_update_rq_clock(struct pt_regs *ctx){
    u32 key = 2;
    u32 rqkey = 0;
    struct rq *p_rq = 0;
    p_rq = (struct rq *)bpf_map_lookup_elem(&rq_map, &rqkey);
    if (!p_rq) {
        return 0;
    }

    bpf_probe_read_kernel(p_rq, sizeof(struct rq), (void *)PT_REGS_PARM1(ctx));
    //使用bpf_probe_read_kernel函数将内核空间中的数据复制到p_rq所指向的内存区域中，以便后续对该数据进行访问和操作。
    u64 val = p_rq->nr_running;
    bpf_map_update_elem(&countMap,&key,&val,BPF_ANY);
    return 0;
}

//软中断
SEC("tracepoint/irq/softirq_entry")
int trace_softirq_entry(struct __softirq_info *info) {

	u32 key = info->vec;//获取软中断向量号，作为 BPF Map 的键
	u64 val = bpf_ktime_get_ns();//获取当前时间
	bpf_map_update_elem(&softirqCpuEnterTime, &key, &val, BPF_ANY);
	return 0;
}

SEC("tracepoint/irq/softirq_exit")
int trace_softirq_exit(struct __softirq_info *info) {

	u32 key = info->vec;
	u64 now = bpf_ktime_get_ns(), *valp = 0;

	valp =bpf_map_lookup_elem(&softirqCpuEnterTime, &key);
	if (valp) {
		// 找到表项
		u64 last_time = now - *valp;
		u32 key0 = 0;

		valp = bpf_map_lookup_elem(&softirqLastTime, &key0);//在lasttime数组中找，因为大小是1
		if (!valp) bpf_map_update_elem(&softirqLastTime, &key0, &last_time, BPF_ANY);
		else *valp += last_time;
	/*当处理软中断退出事件时，代码使用了bpf_map_lookup_elem函数查询softirqLastTime BPF Map中与键key0对应的条目，
	其中key0为常量0，因为softirqLastTime是一个大小为1的数组。如果该条目不存在，则说明这是第一次处理软中断退出事件，
	需要将last_time的值插入到softirqLastTime表中；否则，说明已经统计过该软中断的运行时间，需要将本次运行时间累加到原有的运行时间上。*/
	}	
	return 0;
}