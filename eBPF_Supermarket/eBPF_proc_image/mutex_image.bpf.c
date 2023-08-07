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
// kernel-mode code for the process mutex image

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "mutex_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, pid_t);
	__type(value, struct mutex_event);
} mutex SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 1024);
} mutex_rb SEC(".maps");

SEC("kprobe/mutex_lock")
int kprobe__mutex_lock(struct pt_regs *ctx)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        struct mutex *lock = (struct mutex *)PT_REGS_PARM1(ctx);
        struct mutex_event me = {};

        me.mutex_acq_time = bpf_ktime_get_ns();
        me.pid = pid;
        bpf_get_current_comm(&me.comm, sizeof(me.comm));
        //me.lock_ptr = (u64)lock;
        if(bpf_map_update_elem(&mutex, &pid, &me, BPF_ANY))
            return 0;

        struct mutex_event* e;
        e = bpf_ringbuf_reserve(&mutex_rb, sizeof(*e), 0);
        if(!e)
            return 0;
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        //e->lock_ptr = me.lock_ptr;
        e->mutex_acq_time = me.mutex_acq_time;

        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

SEC("kretprobe/mutex_lock")
int kretprobe__mutex_lock(struct pt_regs *ctx)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        struct mutex_event *me;

        me = bpf_map_lookup_elem(&mutex, &pid);
        if(!me)
            return 0;        //后期迭代在此加分支
        me->mutex_lock_time = bpf_ktime_get_ns();

        struct mutex_event* e;
        e = bpf_ringbuf_reserve(&mutex_rb, sizeof(*e), 0);
        if(!e)
            return 0;
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        //e->lock_ptr = me->lock_ptr;
        e->mutex_acq_time = me->mutex_acq_time;
        e->mutex_lock_time = me->mutex_lock_time;

        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

SEC("kretprobe/mutex_unlock")
int kretprobe__mutex_unlock(struct pt_regs *ctx)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        struct mutex_event *me;

        me = bpf_map_lookup_elem(&mutex, &pid);
        if(!me)
            return 0;
        me->mutex_unlock_time = bpf_ktime_get_ns();

        struct mutex_event* e;
        e = bpf_ringbuf_reserve(&mutex_rb, sizeof(*e), 0);
        if(!e)
            return 0;
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        //e->lock_ptr = me->lock_ptr;
        e->mutex_acq_time = me->mutex_acq_time;
        e->mutex_lock_time = me->mutex_lock_time;
        e->mutex_unlock_time = me->mutex_unlock_time;

        bpf_ringbuf_submit(e, 0);

        bpf_map_delete_elem(&mutex, &pid);
    }

    return 0;
}