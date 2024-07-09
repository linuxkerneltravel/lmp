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

BPF_HASH(mutex_info_map,u64,struct mutex_info, 1024);

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


/*----------------------------------------------*/
/*                内核态互斥锁                   */
/*----------------------------------------------*/

SEC("kprobe/mutex_lock")
int BPF_KPROBE(trace_mutex_lock, struct mutex *lock) {
    u64 lock_addr = (u64)lock;      // 获取锁地址
    u64 ts = bpf_ktime_get_ns();    
    struct mutex_info *info = bpf_map_lookup_elem(&mutex_info_map, &lock_addr);
    if (info) {
        info->acquire_time = ts;  // 保存锁获取时间
    } else {
        struct mutex_info new_info = {
            .locked_total = 0,
            .locked_max = 0,
            .contended_total = 0,
            .last_owner = 0,
            .acquire_time = ts,
            .ptr = lock_addr
        };
        bpf_map_update_elem(&mutex_info_map, &lock_addr, &new_info, BPF_ANY); 
    }
    return 0;
}

SEC("kprobe/mutex_trylock")
int BPF_KPROBE(trace_mutex_trylock, struct mutex *lock) {
    int ret = PT_REGS_RC(ctx);
    if (ret == 0) { // 成功获取锁
        u64 lock_addr = (u64)lock;      // 获取锁地址
        u64 ts = bpf_ktime_get_ns();    
        struct mutex_info *info = bpf_map_lookup_elem(&mutex_info_map, &lock_addr);
        if (info) {
            info->acquire_time = ts;  
        } else {
            struct mutex_info new_info = {
                .locked_total = 0,
                .locked_max = 0,
                .contended_total = 0,
                .last_owner = 0,
                .acquire_time = ts,
                .ptr = lock_addr
            };
            bpf_map_update_elem(&mutex_info_map, &lock_addr, &new_info, BPF_ANY);
        }
    }
    return 0;
}

SEC("kprobe/__mutex_lock_slowpath")
int BPF_KPROBE(trace_mutex_lock_slowpath, struct mutex *lock) {
    struct mutex_contention_event *e;
    struct task_struct *owner_task;
    struct task_struct *contender_task;
    pid_t pid = bpf_get_current_pid_tgid();
    long owner;
    u64 lock_addr = (u64)lock;
    u64 ts = bpf_ktime_get_ns();
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    e->contender_pid = pid;
    e->ptr = lock_addr;
    bpf_get_current_comm(&e->contender_name, sizeof(e->contender_name));
    bpf_probe_read_kernel(&owner, sizeof(owner), &lock->owner);
    owner_task = (struct task_struct *)(owner & ~0x1L);
    contender_task = (struct task_struct *)bpf_get_current_task();
     bpf_probe_read_kernel(&e->contender_prio, sizeof(e->contender_prio), &contender_task->prio);
    if (owner_task) {
        bpf_probe_read_kernel(&e->owner_pid, sizeof(e->owner_pid), &owner_task->pid);
        bpf_probe_read_kernel_str(&e->owner_name, sizeof(e->owner_name), owner_task->comm);
        bpf_probe_read_kernel(&e->owner_prio, sizeof(e->owner_prio), &owner_task->prio);
    } else {
        e->owner_pid = 0;
        __builtin_memset(e->owner_name, 0, sizeof(e->owner_name));
    }
    struct mutex_info *info = bpf_map_lookup_elem(&mutex_info_map, &lock_addr);
    if (info) {
        info->contended_total += ts - info->acquire_time;
    } else {
        struct mutex_info new_info = {
            .locked_total = 0,
            .locked_max = 0,
            .contended_total = ts,
            .last_owner = 0,
            .acquire_time = 0,
            .ptr = lock_addr
        };
        bpf_map_update_elem(&mutex_info_map, &lock_addr, &new_info, BPF_ANY);
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/mutex_unlock")
int BPF_KPROBE(trace_mutex_unlock, struct mutex *lock) {
    u64 lock_addr = (u64)lock;
    u64 ts = bpf_ktime_get_ns();
    pid_t pid = bpf_get_current_pid_tgid();
    struct mutex_info *info = bpf_map_lookup_elem(&mutex_info_map, &lock_addr);
    if (info) {
        u64 held_time = ts - info->acquire_time; // 计算锁被持有的时间
        info->locked_total += held_time;         // 更新锁被持有的总时间
        if (held_time > info->locked_max) {
            info->locked_max = held_time;        // 更新锁被持有的最长时间
        }
        info->last_owner = pid;                  // 更新最后一次持有该锁的线程ID
    }
    return 0;
}

/*----------------------------------------------*/
/*                用户态互斥锁                   */
/*----------------------------------------------*/

// SEC("uprobe")
// int BPF_KPROBE(pthread_mutex_lock_init, pthread_mutex_t *mutex){

// }

// SEC("uprobe")
// int BPF_KPROBE(pthread_mutex_lock,pthread_mutex_t *mutex){
    
// }

// SEC("uprobe")
// int BPF_KPROBE(pthread_mutex_try, pthread_mutex_t *mutex){
    
// }

// SEC("uprobe")
// int BPF_KPROBE(pthread_mutex_unlock, pthread_mutex_t *mutex){
    
// }

// SEC("uprobe")
// int BPF_KPROBE(pthread_mutex_destroy, pthread_mutex_t *mutex){
    
// }