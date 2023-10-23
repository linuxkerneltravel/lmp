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
// kernel-mode code for the process lock image

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "lock_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t target_pid = 0;
const volatile bool enable_u_mutex = false;
const volatile bool enable_k_mutex = false;
const volatile bool enable_u_rwlock_rd = false;
const volatile bool enable_u_rwlock_wr = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, u64);
} proc_lock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, u64);
} proc_unlock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct proc_lockptr);
	__type(value, struct lock_event);
} lock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 1024);
} lock_rb SEC(".maps");

static int record_lock_enter(void *__lock,int type)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        u64 lock_ptr = (u64)__lock;
        struct proc_lockptr proc_lockptr = {};
        struct lock_event lock_event = {};

        if(bpf_map_update_elem(&proc_lock, &pid, &lock_ptr, BPF_ANY))
            return 0;

        proc_lockptr.pid = pid;
        proc_lockptr.lock_ptr = lock_ptr;

        lock_event.type = type;
        lock_event.pid = pid;
        bpf_get_current_comm(&lock_event.comm, sizeof(lock_event.comm));
        lock_event.lock_ptr = lock_ptr;
        lock_event.lock_acq_time = bpf_ktime_get_ns();

        if(bpf_map_update_elem(&lock, &proc_lockptr, &lock_event, BPF_ANY))
            return 0;

        struct lock_event* e;
        e = bpf_ringbuf_reserve(&lock_rb, sizeof(*e), 0);
        if(!e)
            return 0;
        
        e->type = type;
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->lock_ptr = lock_ptr;
        e->lock_acq_time = lock_event.lock_acq_time;

        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

static int record_lock_exit()
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        u64 *lock_ptr;
        struct proc_lockptr proc_lockptr = {};
        struct lock_event *lock_event;

        lock_ptr = bpf_map_lookup_elem(&proc_lock, &pid);
        if(!lock_ptr)
            return 0;

        proc_lockptr.pid = pid;
        proc_lockptr.lock_ptr = *lock_ptr;

        lock_event = bpf_map_lookup_elem(&lock, &proc_lockptr);
        if(!lock_event)
            return 0;

        lock_event->lock_time = bpf_ktime_get_ns();

        struct lock_event* e;
        e = bpf_ringbuf_reserve(&lock_rb, sizeof(*e), 0);
        if(!e)
            return 0;
        
        e->type = lock_event->type;
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->lock_ptr = *lock_ptr;
        e->lock_acq_time = lock_event->lock_acq_time;
        e->lock_time = lock_event->lock_time;

        bpf_ringbuf_submit(e, 0);

        bpf_map_delete_elem(&proc_lock, &pid);
    }

    return 0;
}

static int record_unlock_enter(void *__lock)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        u64 lock_ptr = (u64)__lock;
        if(bpf_map_update_elem(&proc_unlock, &pid, &lock_ptr, BPF_ANY))
            return 0;
    }

    return 0;
}

static int record_unlock_exit()
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        u64 *lock_ptr;
        struct proc_lockptr proc_lockptr = {};
        struct lock_event *lock_event;
        
        lock_ptr = bpf_map_lookup_elem(&proc_unlock, &pid);
        if(!lock_ptr)
            return 0;

        proc_lockptr.pid = pid;
        proc_lockptr.lock_ptr = *lock_ptr;

        lock_event = bpf_map_lookup_elem(&lock, &proc_lockptr);
        if(!lock_event)
            return 0;
        lock_event->unlock_time = bpf_ktime_get_ns();

        struct lock_event* e;
        e = bpf_ringbuf_reserve(&lock_rb, sizeof(*e), 0);
        if(!e)
            return 0;
        
        e->type = lock_event->type;
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->lock_ptr = *lock_ptr;
        e->lock_acq_time = lock_event->lock_acq_time;
        e->lock_time = lock_event->lock_time;
        e->unlock_time = lock_event->unlock_time;

        bpf_ringbuf_submit(e, 0);

        bpf_map_delete_elem(&proc_unlock, &pid);

        bpf_map_delete_elem(&lock, &proc_lockptr);
    }

    return 0;
}

// 用户态互斥锁
SEC("uprobe/pthread_mutex_lock")
int BPF_KPROBE(pthread_mutex_lock_enter, void *__mutex)
{
    if(enable_u_mutex){
        record_lock_enter(__mutex,1);
    }

    return 0;
}

SEC("uretprobe/pthread_mutex_lock")
int BPF_KRETPROBE(pthread_mutex_lock_exit)
{
    if(enable_u_mutex){
        record_lock_exit();
    }

    return 0;
}

SEC("uprobe/__pthread_mutex_trylock")
int BPF_KPROBE(__pthread_mutex_trylock_enter, void *__mutex)
{
    if(enable_u_mutex){
        record_lock_enter(__mutex,1);
    }

    return 0;
}

SEC("uretprobe/__pthread_mutex_trylock")
int BPF_KRETPROBE(__pthread_mutex_trylock_exit)
{
    if(enable_u_mutex){
        record_lock_exit();
    }
    
    return 0;
}

SEC("uprobe/pthread_mutex_unlock")
int BPF_KPROBE(pthread_mutex_unlock_enter, void *__rwlock)
{
    if(enable_u_mutex){
        record_unlock_enter(__rwlock);
    }
    
    return 0;
}

SEC("uretprobe/pthread_mutex_unlock")
int BPF_KRETPROBE(pthread_mutex_unlock_exit)
{
    if(enable_u_mutex){
        record_unlock_exit();
    }
    
    return 0;
}

// 内核态互斥锁
SEC("kprobe/mutex_lock")
int kprobe__mutex_lock(struct pt_regs *ctx)
{
    if(enable_k_mutex){
        struct mutex *lock = (struct mutex *)PT_REGS_PARM1(ctx);
        record_lock_enter(lock,2);
    }

    return 0;
}

SEC("kretprobe/mutex_lock")
int kretprobe__mutex_lock()
{
    if(enable_k_mutex){
        record_lock_exit();
    }

    return 0;
}

SEC("kprobe/mutex_trylock")
int kprobe__mutex_trylock(struct pt_regs *ctx)
{
    if(enable_k_mutex){
        struct mutex *lock = (struct mutex *)PT_REGS_PARM1(ctx);
        record_lock_enter(lock,2);
    }

    return 0;
}

SEC("kretprobe/mutex_trylock")
int kretprobe__mutex_trylock()
{
    if(enable_k_mutex){
        record_lock_exit();
    }

    return 0;
}

SEC("kprobe/mutex_unlock")
int kprobe__mutex_unlock(struct pt_regs *ctx)
{
    if(enable_k_mutex){
        struct mutex *lock = (struct mutex *)PT_REGS_PARM1(ctx);
        record_unlock_enter(lock);
    }

    return 0;
}

SEC("kretprobe/mutex_unlock")
int kretprobe__mutex_unlock()
{
    if(enable_k_mutex){
        record_unlock_exit();
    }
    
    return 0;
}

// 用户态读写锁
SEC("uprobe/__pthread_rwlock_rdlock")
int BPF_KPROBE(__pthread_rwlock_rdlock_enter, void *__rwlock)
{
    if(enable_u_rwlock_rd){
        record_lock_enter(__rwlock,3);
    }

    return 0;
}

SEC("uretprobe/__pthread_rwlock_rdlock")
int BPF_KRETPROBE(__pthread_rwlock_rdlock_exit)
{
    if(enable_u_rwlock_rd){
        record_lock_exit();
    }

    return 0;
}

SEC("uprobe/__pthread_rwlock_tryrdlock")
int BPF_KPROBE(__pthread_rwlock_tryrdlock_enter, void *__rwlock)
{
    if(enable_u_rwlock_rd){
        record_lock_enter(__rwlock,3);
    }
    
    return 0;
}

SEC("uretprobe/__pthread_rwlock_tryrdlock")
int BPF_KRETPROBE(__pthread_rwlock_tryrdlock_exit)
{
    if(enable_u_rwlock_rd){
        record_lock_exit();
    }

    return 0;
}

SEC("uprobe/__pthread_rwlock_wrlock")
int BPF_KPROBE(__pthread_rwlock_wrlock_enter, void *__rwlock)
{
    if(enable_u_rwlock_wr){
        record_lock_enter(__rwlock,4);
    }
    
    return 0;
}

SEC("uretprobe/__pthread_rwlock_wrlock")
int BPF_KRETPROBE(__pthread_rwlock_wrlock_exit)
{
    if(enable_u_rwlock_wr){
        record_lock_exit();
    }

    return 0;
}

SEC("uprobe/__pthread_rwlock_trywrlock")
int BPF_KPROBE(__pthread_rwlock_trywrlock_enter, void *__rwlock)
{
    if(enable_u_rwlock_wr){
        record_lock_enter(__rwlock,4);
    }

    return 0;
}

SEC("uretprobe/__pthread_rwlock_trywrlock")
int BPF_KRETPROBE(__pthread_rwlock_trywrlock_exit)
{
    if(enable_u_rwlock_wr){
        record_lock_exit();
    }

    return 0;
}

SEC("uprobe/__pthread_rwlock_unlock")
int BPF_KPROBE(__pthread_rwlock_unlock_enter, void *__rwlock)
{
    if(enable_u_rwlock_rd || enable_u_rwlock_wr){
        record_unlock_enter(__rwlock);
    }

    return 0;
}

SEC("uretprobe/__pthread_rwlock_unlock")
int BPF_KRETPROBE(__pthread_rwlock_unlock_exit)
{
    if(enable_u_rwlock_rd || enable_u_rwlock_wr){
        record_unlock_exit();
    }
    
    return 0;
}