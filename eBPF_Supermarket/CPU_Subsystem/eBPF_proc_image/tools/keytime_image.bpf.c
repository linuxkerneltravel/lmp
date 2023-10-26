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
// kernel-mode code for the process key time image

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "keytime_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t target_pid = 0;
const volatile bool enable_execve = false;
const volatile bool enable_exit = false;
const volatile int max_args = DEFAULT_MAXARGS;

static const struct event empty_event = {};

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, struct event);
} keytime SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static void output_keytime_enter(struct trace_event_raw_sys_enter* ctx,struct event *event)
{
	size_t len = EVENT_SIZE(event);
	if (len <= sizeof(*event))
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, len);
}

static int record_exitsys(struct trace_event_raw_sys_enter* ctx)
{
	if(enable_exit){
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		int pid = BPF_CORE_READ(task,pid);
		if(pid == target_pid){
			struct event *event;

			if (bpf_map_update_elem(&keytime, &pid, &empty_event, BPF_NOEXIST))
				return 0;

			event = bpf_map_lookup_elem(&keytime, &pid);
			if (!event)
				return 0;
			
			event->flag = 3;
			event->pid = pid;
			event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, pid);
			bpf_get_current_comm(&event->comm, sizeof(event->comm));
			event->start = bpf_ktime_get_ns();
			event->enable_char_args = false;
			event->args_count = 1;
			event->ctx_args[0] = ctx->args[0];

			output_keytime_enter(ctx,event);

			bpf_map_delete_elem(&keytime, &pid);
		}
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	if(enable_execve){
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		int pid = BPF_CORE_READ(task,pid);
		if(pid == target_pid){
			int ret;
			int i;
			struct event *event;
			const char **args = (const char **)(ctx->args[1]);
			const char *argp;

			if (bpf_map_update_elem(&keytime, &pid, &empty_event, BPF_NOEXIST))
				return 0;

			event = bpf_map_lookup_elem(&keytime, &pid);
			if (!event)
				return 0;

			event->flag = 1;
			event->pid = pid;
			event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, pid);
			bpf_get_current_comm(&event->comm, sizeof(event->comm));
			event->start = bpf_ktime_get_ns();
			event->exit = 0;
			event->args_count = 0;
			event->args_size = 0;

			event->enable_char_args = true;
			ret = bpf_probe_read_user_str(event->args, ARGSIZE, (const char*)ctx->args[0]);
			if (ret < 0) {
				output_keytime_enter(ctx,event);
				return 0;
			}
			if (ret <= ARGSIZE) {
				event->args_size += ret;
			} else {
				/* 写一个空字符串 */
				event->args[0] = '\0';
				event->args_size++;
			}

			event->args_count++;
			#pragma unroll
			for (i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
				ret = bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
				if (ret < 0){
					output_keytime_enter(ctx,event);
					return 0;
				}

				if (event->args_size > LAST_ARG){
					output_keytime_enter(ctx,event);
					return 0;
				}

				ret = bpf_probe_read_user_str(&event->args[event->args_size], ARGSIZE, argp);
				if (ret < 0){
					output_keytime_enter(ctx,event);
					return 0;
				}

				event->args_count++;
				event->args_size += ret;
			}
			/* 试着再读一个参数来检查是否有 */
			ret = bpf_probe_read_user(&argp, sizeof(argp), &args[max_args]);
			if (ret < 0){
				output_keytime_enter(ctx,event);
				return 0;
			}

			/* 指向max_args+1的指针不为空，假设我们有更多的参数 */
			event->args_count++;

			output_keytime_enter(ctx,event);
		}
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
	if(enable_execve){
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		int pid = BPF_CORE_READ(task,pid);
		if(pid == target_pid){
			int ret;
			struct event *event;

			ret = ctx->ret;
			if (ret < 0)
				goto cleanup;
			
			event = bpf_map_lookup_elem(&keytime, &pid);
			if (!event){
				if (bpf_map_update_elem(&keytime, &pid, &empty_event, BPF_NOEXIST))
					return 0;

				event = bpf_map_lookup_elem(&keytime, &pid);
				if (!event)
					return 0;

				event->flag = 2;
				event->pid = pid;
				event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, pid);
				bpf_get_current_comm(&event->comm, sizeof(event->comm));
				event->exit = bpf_ktime_get_ns();
				event->retval = ret;
			}else{
				event->flag = 2;
				event->exit = bpf_ktime_get_ns();
				event->retval = ret;
			}

			size_t len = EVENT_SIZE(event);
			if (len <= sizeof(*event))
				bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, len);

		cleanup:
			bpf_map_delete_elem(&keytime, &pid);
		}
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int tracepoint__syscalls__sys_enter_exit_group(struct trace_event_raw_sys_enter* ctx)
{
	record_exitsys(ctx);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int tracepoint__syscalls__sys_enter_exit(struct trace_event_raw_sys_enter* ctx)
{
	record_exitsys(ctx);

	return 0;
}
