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
// Variable definitions and help functions for keytime in the process

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "proc_image.h"

const volatile int max_args = DEFAULT_MAXARGS;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, pid_t);
	__type(value, struct event);
} keytime SEC(".maps");

static int record_enter_execve(struct trace_event_raw_sys_enter* ctx, pid_t target_pid, void *events)
{
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

        event->type = 3;
        event->pid = pid;
        event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, pid);
        event->cpu_id = bpf_get_smp_processor_id();
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        event->start = bpf_ktime_get_ns();
        event->args_count = 0;
        event->args_size = 0;
        event->enable_char_args = true;
        
        ret = bpf_probe_read_user_str(event->args, ARGSIZE, (const char*)ctx->args[0]);
        if (ret < 0) {
            output_event(ctx,event,events);
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
                output_event(ctx,event,events);
                return 0;
            }

            if (event->args_size > LAST_ARG){
                output_event(ctx,event,events);
                return 0;
            }

            ret = bpf_probe_read_user_str(&event->args[event->args_size], ARGSIZE, argp);
            if (ret < 0){
                output_event(ctx,event,events);
                return 0;
            }

            event->args_count++;
            event->args_size += ret;
        }
        /* 试着再读一个参数来检查是否有 */
        ret = bpf_probe_read_user(&argp, sizeof(argp), &args[max_args]);
        if (ret < 0){
            output_event(ctx,event,events);
            return 0;
        }

        /* 指向max_args+1的指针不为空，假设我们有更多的参数 */
        event->args_count++;

        output_event(ctx,event,events);
    }

    return 0;
}

static int record_exit_execve(struct trace_event_raw_sys_exit* ctx, pid_t target_pid, void *events)
{
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

            event->type = 4;
            event->pid = pid;
            event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, pid);
            event->cpu_id = bpf_get_smp_processor_id();
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            event->exit = bpf_ktime_get_ns();
            event->retval = ret;
        }else{
            event->type = 4;
            event->exit = bpf_ktime_get_ns();
            event->retval = ret;
        }

        output_event(ctx,event,events);

    cleanup:
        bpf_map_delete_elem(&keytime, &pid);
    }

    return 0;
}

static int record_exit(struct trace_event_raw_sys_enter* ctx, pid_t target_pid, void *events)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int pid = BPF_CORE_READ(task,pid);
    if(pid == target_pid){
        struct event *event;

        if (bpf_map_update_elem(&keytime, &pid, &empty_event, BPF_NOEXIST))
            return 0;

        event = bpf_map_lookup_elem(&keytime, &pid);
        if (!event)
            return 0;
        
        event->type = 5;
        event->pid = pid;
        event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, pid);
        event->cpu_id = bpf_get_smp_processor_id();
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        event->start = bpf_ktime_get_ns();
        event->enable_char_args = false;
        event->args_count = 1;
        event->ctx_args[0] = ctx->args[0];

        output_event(ctx,event,events);

        bpf_map_delete_elem(&keytime, &pid);
    }

	return 0;
}
