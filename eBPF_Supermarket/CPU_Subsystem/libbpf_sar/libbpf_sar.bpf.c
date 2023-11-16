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
struct __softirq_info {
	u64 pad;
	u32 vec;
};

// 计数表格，第0项为上下文切换次数，第1项为总共新建进程个数
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, u64);
} countMap SEC(".maps");
//记录软中断开始时间
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, u64);
} softirqCpuEnterTime SEC(".maps");
//软中断结束时间
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} softirqLastTime SEC(".maps");

// 统计fork数
SEC("kprobe/finish_task_switch")
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

//统计软中断执行时间
SEC("tracepoint/irq/softirq_entry")
int trace_softirq_entry(struct __softirq_info *info) {
	u32 key = info->vec;
	u64 val = bpf_ktime_get_ns();
	bpf_map_update_elem(&softirqCpuEnterTime, &key, &val, BPF_ANY);
	return 0;
}

SEC("tracepoint/irq/softirq_exit")
int trace_softirq_exit(struct __softirq_info *info) {
	u32 key = info->vec;
	u64 now = bpf_ktime_get_ns(), *valp = 0;
	valp =bpf_map_lookup_elem(&softirqCpuEnterTime, &key);
	if (valp) {
		u64 last_time = now - *valp;
		u32 key0 = 0;
		valp = bpf_map_lookup_elem(&softirqLastTime, &key0);
		if (!valp) bpf_map_update_elem(&softirqLastTime, &key0, &last_time, BPF_ANY);
		else *valp += last_time;	
	return 0;
    }
}