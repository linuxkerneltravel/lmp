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
// Variable definitions and help functions for lock in the process

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"

struct proc_flag{
    int pid;
    // 1代表用户态互斥锁
    // 2代表内核态互斥锁
    // 3代表用户态读写锁
    int flag;
};

struct proc_lockptr{
    int pid;
    long long unsigned int lock_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct proc_flag);
	__type(value, u64);
} proc_lock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct proc_flag);
	__type(value, u64);
} proc_unlock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct proc_lockptr);
	__type(value, struct event);
} lock SEC(".maps");

static int record_lock_enter(void *ctx,int type,int flag,void *__lock,int target_pid,void *events)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        u64 lock_ptr = (u64)__lock;
        struct proc_lockptr proc_lockptr = {};
        struct proc_flag proc_flag = {};
        struct event *event;
        
	    proc_flag.pid = pid;
        proc_flag.flag = flag;
        
        if(bpf_map_update_elem(&proc_lock, &proc_flag, &lock_ptr, BPF_ANY))
            return 0;

        proc_lockptr.pid = pid;
        proc_lockptr.lock_ptr = lock_ptr;
        
        
        if (bpf_map_update_elem(&lock, &proc_lockptr, &empty_event, BPF_NOEXIST))
            return 0;

        event = bpf_map_lookup_elem(&lock, &proc_lockptr);
        if (!event)
            return 0;

        event->type = type;
        event->pid = pid;
        event->ppid = (pid_t)BPF_CORE_READ(current, real_parent, pid);
        event->cpu_id = bpf_get_smp_processor_id();
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        event->start = bpf_ktime_get_ns();
        event->enable_char_args = false;
        event->args_count = 1;
        event->ctx_args[0] = lock_ptr;

        output_event(ctx,event,events);
    }

    return 0;
}

static int record_lock_exit(void *ctx,int flag,int ret,int target_pid,void *events)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        u64 *lock_ptr;
        struct proc_lockptr proc_lockptr = {};
        struct event *event;
        struct proc_flag proc_flag = {};

        proc_flag.pid = pid;
        proc_flag.flag = flag;

        lock_ptr = bpf_map_lookup_elem(&proc_lock, &proc_flag);
        if(!lock_ptr)
            return 0;

        proc_lockptr.pid = pid;
        proc_lockptr.lock_ptr = *lock_ptr;

        event = bpf_map_lookup_elem(&lock, &proc_lockptr);
        if(!event)
            return 0;

        event->type ++;
        event->exit = bpf_ktime_get_ns();
        event->retval = ret;

        output_event(ctx,event,events);

        event->start = event->exit;

        bpf_map_delete_elem(&proc_lock, &proc_flag);
    }

    return 0;
}

static int record_unlock_enter(int flag,void *__lock,int target_pid)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        u64 lock_ptr = (u64)__lock;
        struct proc_flag proc_flag = {};

        proc_flag.pid = pid;
        proc_flag.flag = flag;

        if(bpf_map_update_elem(&proc_unlock, &proc_flag, &lock_ptr, BPF_ANY))
            return 0;
    }

    return 0;
}

static int record_unlock_exit(void *ctx,int flag,int target_pid,void *events)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        u64 *lock_ptr;
        struct proc_lockptr proc_lockptr = {};
        struct event *event;
        struct proc_flag proc_flag = {};

        proc_flag.pid = pid;
        proc_flag.flag = flag;
        
        lock_ptr = bpf_map_lookup_elem(&proc_unlock, &proc_flag);
        if(!lock_ptr)
            return 0;

        proc_lockptr.pid = pid;
        proc_lockptr.lock_ptr = *lock_ptr;

        event = bpf_map_lookup_elem(&lock, &proc_lockptr);
        if(!event)
            return 0;
        event->type ++;
        event->exit = bpf_ktime_get_ns();

        output_event(ctx,event,events);

        bpf_map_delete_elem(&proc_unlock, &proc_flag);

        bpf_map_delete_elem(&lock, &proc_lockptr);
    }

    return 0;
}
