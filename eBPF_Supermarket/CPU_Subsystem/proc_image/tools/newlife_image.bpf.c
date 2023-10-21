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
// kernel-mode code for the new life image

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "newlife_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t target_pid = 0;
const volatile bool enable_fork = false;
const volatile bool enable_vfork = false;
const volatile bool enable_newthread = false;

/*
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, pid_t);
	__type(value, int);
} pthread_create_enable SEC(".maps");
*/
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct bind_pid);
	__type(value, struct newlife_start);
} newstart SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 1024);
} newlife_rb SEC(".maps");

// 记录开始时间，并输出到 ringbuf 中
static int newlife_create(int flag, pid_t newlife_pid)
{
	struct bind_pid bind_pid = {};
	struct newlife_start newlife_start = {};

	bind_pid.pid = target_pid;
	bind_pid.newlife_pid = newlife_pid;
	newlife_start.start = bpf_ktime_get_ns();
	newlife_start.flag = flag;
	if(bpf_map_update_elem(&newstart, &bind_pid, &newlife_start, BPF_ANY))
		return 0;
	
	struct newlife_event *e;
	e = bpf_ringbuf_reserve(&newlife_rb, sizeof(*e), 0);
	if(!e)
		return 0;
	e->flag = flag;
	e->newlife_pid = newlife_pid;
	e->start = newlife_start.start;

	bpf_ringbuf_submit(e, 0);

	return 0;
}

// 记录退出时间，并输出到 ringbuf 中
static int newlife_exit()
{
	struct bind_pid bind_pid = {};
	struct newlife_start *newlife_start;

	bind_pid.pid = target_pid;
	bind_pid.newlife_pid = bpf_get_current_pid_tgid();

	newlife_start = bpf_map_lookup_elem(&newstart, &bind_pid);
	if(!newlife_start)
        return 0;
	
	struct newlife_event *e;
	e = bpf_ringbuf_reserve(&newlife_rb, sizeof(*e), 0);
    if(!e)
        return 0;
	e->flag = newlife_start->flag;
	e->newlife_pid = bind_pid.newlife_pid;
	e->start = newlife_start->start;
	e->exit = bpf_ktime_get_ns();

	bpf_ringbuf_submit(e, 0);

	bpf_map_delete_elem(&newstart, &bind_pid);

	return 0;
}

// 记录 fork 子进程的开始时间，并输出到 ringbuf 中
SEC("uretprobe/fork")
int BPF_KRETPROBE(fork_exit,int ret)
{
	if(enable_fork){
		// 判断是否为子进程触发
		if(ret != 0)	return 0;

		pid_t child_pid = bpf_get_current_pid_tgid();
		newlife_create(1,child_pid);
	}

	return 0;
}

// 记录 vfork 子进程的开始时间，并输出到 ringbuf 中
SEC("uretprobe/vfork")
int BPF_KRETPROBE(vfork_exit,int ret)
{
	if(enable_vfork){
		// 判断是否为子进程触发
		if(ret != 0)	return 0;

		pid_t child_pid = bpf_get_current_pid_tgid();
		newlife_create(2,child_pid);
	}

	return 0;
}

// 记录 fork 和 vfork 子进程的退出时间，并输出到 ringbuf 中
SEC("tracepoint/syscalls/sys_enter_exit_group")
int tracepoint__syscalls__sys_enter_exit_group(struct trace_event_raw_sys_enter* ctx)
{
	if(enable_fork || enable_vfork){
		newlife_exit();
	}

	return 0;
}

/*
SEC("uprobe/pthread_create")
int BPF_KPROBE(pthread_create_enter)
{
	if(enable_newthread){
		int current = target_pid;
		int pthread_create_flag = 1;

		bpf_map_update_elem(&pthread_create_enable, &current, &pthread_create_flag, BPF_ANY);
	}

	return 0;
}

SEC("uretprobe/pthread_create")
int BPF_KRETPROBE(pthread_create_exit,int ret)
{
	if(enable_newthread){
		int current = target_pid;
		bpf_map_delete_elem(&pthread_create_enable, &current);
	}
	return 0;
}
*/

// 记录 pthread_create 新线程的开始时间，并输出到 ringbuf 中
SEC("tracepoint/syscalls/sys_exit_clone3")
int tracepoint__syscalls__sys_exit_clone3(struct trace_event_raw_sys_exit* ctx)
{
	if(enable_newthread){
		pid_t current = bpf_get_current_pid_tgid();

		if(current == target_pid)
		{
			/*
			// 判断是否是pthread_create函数触发的clone3系统调用
			int *pthread_create_flag;
			pthread_create_flag = bpf_map_lookup_elem(&pthread_create_enable, &current);
			if(!pthread_create_flag)
				return 0;
			*/

			pid_t new_thread = ctx->ret;
			// 排除clone3错误返回的情况
			if(new_thread <= 0)	return 0;

			newlife_create(3,new_thread);
		}
	}

	return 0;
}

// 记录 pthread_create 新线程的退出时间，并输出到 ringbuf 中
SEC("tracepoint/syscalls/sys_enter_exit")
int tracepoint__syscalls__sys_enter_exit(struct trace_event_raw_sys_enter* ctx)
{
	if(enable_newthread){
		newlife_exit();
	}

	return 0;
}