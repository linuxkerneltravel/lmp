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
// eBPF kernel-mode code that collects process key time information

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int max_args = DEFAULT_MAXARGS;

const volatile pid_t target_pid = -1;
/*
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, struct keytime_event);
} keytime SEC(".maps");
*/
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 10240);
} keytime_rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    int pid = bpf_get_current_pid_tgid();
    if(target_pid==-1 || pid==target_pid){
        struct keytime_event* event;
        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;
        
        int ret;
        int i;
        const char **args = (const char **)(ctx->args[1]);
        const char *argp;

        event->type = 1;
        event->pid = pid;
        event->info_count = 0;
        event->info_size = 0;
        event->enable_char_info = true;

        ret = bpf_probe_read_user_str(event->char_info, ARGSIZE, (const char*)ctx->args[0]);
        if (ret < 0) {
            bpf_ringbuf_submit(event, 0);
            return 0;
        }
        if (ret <= ARGSIZE) {
            event->info_size += ret;
        } else {
            /* 写一个空字符串 */
            event->char_info[0] = '\0';
            event->info_size++;
        }

        event->info_count++;
        #pragma unroll
        for (i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
            ret = bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
            if (ret < 0){
                bpf_ringbuf_submit(event, 0);
                return 0;
            }

            if (event->info_size > LAST_ARG){
                bpf_ringbuf_submit(event, 0);
                return 0;
            }

            ret = bpf_probe_read_user_str(&event->char_info[event->info_size], ARGSIZE, argp);
            if (ret < 0){
                bpf_ringbuf_submit(event, 0);
                return 0;
            }

            event->info_count++;
            event->info_size += ret;
        }
        /* 试着再读一个参数来检查是否有 */
        ret = bpf_probe_read_user(&argp, sizeof(argp), &args[max_args]);
        if (ret < 0){
            bpf_ringbuf_submit(event, 0);
            return 0;
        }

        /* 指向max_args+1的指针不为空，假设我们有更多的参数 */
        event->info_count++;

        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
    int pid = bpf_get_current_pid_tgid();
    if(target_pid==-1 || pid==target_pid){
        struct keytime_event* event;
        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;

        event->type = 2;
        event->pid = pid;
        event->enable_char_info = false;
        event->info_count = 1;
        event->info[0] = ctx->ret;

        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int tracepoint__syscalls__sys_enter_exit_group(struct trace_event_raw_sys_enter* ctx)
{
    int pid = bpf_get_current_pid_tgid();
    if(target_pid==-1 || pid==target_pid){
        struct keytime_event* event;
        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;
        
        event->type = 3;
        event->pid = pid;
        event->enable_char_info = false;
        event->info_count = 1;
        event->info[0] = ctx->args[0];

        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int tracepoint__syscalls__sys_enter_exit(struct trace_event_raw_sys_enter* ctx)
{
    int pid = bpf_get_current_pid_tgid();
    if(target_pid==-1 || pid==target_pid){
        struct keytime_event* event;
        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;
        
        event->type = 3;
        event->pid = pid;
        event->enable_char_info = false;
        event->info_count = 1;
        event->info[0] = ctx->args[0];

        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}