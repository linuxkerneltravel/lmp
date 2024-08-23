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

const int ctrl_key = 0;
BPF_HASH(kmutex_info_map, u64, struct mutex_info, 1024);
BPF_HASH(umutex_info_map, u64, struct mutex_info, 1024);
BPF_HASH(trylock_map, u64, struct trylock_info, 1024);
BPF_ARRAY(mu_ctrl_map, int, struct mu_ctrl, 1);
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline struct mu_ctrl *get_mu_ctrl(void) {
    struct mu_ctrl *mu_ctrl;
    mu_ctrl = bpf_map_lookup_elem(&mu_ctrl_map, &ctrl_key);
    if (!mu_ctrl || !mu_ctrl->mu_func) {
        return NULL;
    }
    return mu_ctrl;
}

/*----------------------------------------------*/
/*                内核态互斥锁                   */
/*----------------------------------------------*/

SEC("kprobe/mutex_lock")
int BPF_KPROBE(trace_mutex_lock, struct mutex *lock) {
    u64 lock_addr = (u64)lock; // 获取锁地址
    u64 ts = bpf_ktime_get_ns();
    struct mutex_info *info = bpf_map_lookup_elem(&kmutex_info_map, &lock_addr);
    if (info) {
        info->acquire_time = ts; // 保存锁获取时间
    } else {
        struct mutex_info new_info = {
            .locked_total = 0,
            .locked_max = 0,
            .contended_total = 0,
            .count = 0,
            .last_owner = 0,
            .acquire_time = ts,
            .ptr = lock_addr
        };
        __builtin_memset(new_info.last_name, 0, sizeof(new_info.last_name));
        bpf_map_update_elem(&kmutex_info_map, &lock_addr, &new_info, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/mutex_trylock")
int BPF_KPROBE(trace_mutex_trylock, struct mutex *lock) {
    int ret = PT_REGS_RC(ctx);
    if (ret != 0) { // 成功获取锁
        u64 lock_addr = (u64)lock; // 获取锁地址
        u64 ts = bpf_ktime_get_ns();
        struct mutex_info *info = bpf_map_lookup_elem(&kmutex_info_map, &lock_addr);
        if (info) {
            info->acquire_time = ts;
        } else {
            struct mutex_info new_info = {
                .locked_total = 0,
                .locked_max = 0,
                .contended_total = 0,
                .count = 0,
                .last_owner = 0,
                .acquire_time = ts,
                .ptr = lock_addr
            };
            __builtin_memset(new_info.last_name, 0, sizeof(new_info.last_name));
            bpf_map_update_elem(&kmutex_info_map, &lock_addr, &new_info, BPF_ANY);
        }
    }
    return 0;
}

SEC("kprobe/__mutex_lock_slowpath")
int BPF_KPROBE(trace_mutex_lock_slowpath, struct mutex *lock) {
    struct mu_ctrl *mu_ctrl = get_mu_ctrl();
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
    struct mutex_info *info = bpf_map_lookup_elem(&kmutex_info_map, &lock_addr);
    if (info) {
        u64 contention_start = ts;
        info->contended_total += (contention_start - info->acquire_time); // 更新争用时间
        info->count++; // 更新争用次数
    } else {
        struct mutex_info new_info = {
            .locked_total = 0,
            .locked_max = 0,
            .contended_total = 0,
            .count = 1, // 初始化争用次数
            .last_owner = 0,
            .acquire_time = ts, // 初始化获取时间
            .ptr = lock_addr
        };
        __builtin_memset(new_info.last_name, 0, sizeof(new_info.last_name));
        bpf_map_update_elem(&kmutex_info_map, &lock_addr, &new_info, BPF_ANY);
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/mutex_unlock")
int BPF_KPROBE(trace_mutex_unlock, struct mutex *lock) {
    u64 lock_addr = (u64)lock;
    u64 ts = bpf_ktime_get_ns();
    pid_t pid = bpf_get_current_pid_tgid();
    struct mutex_info *info = bpf_map_lookup_elem(&kmutex_info_map, &lock_addr);
    if (info) {
        u64 held_time = ts - info->acquire_time; // 计算锁被持有的时间
        info->locked_total += held_time;         // 更新锁被持有的总时间
        if (held_time > info->locked_max) {
            info->locked_max = held_time;        // 更新锁被持有的最长时间
        }
        info->last_owner = pid;                  // 更新最后一次持有该锁的线程ID
        bpf_get_current_comm(&info->last_name, sizeof(info->last_name)); // 更新最后一次持有该锁的线程名称
    }
    return 0;
}



/*----------------------------------------------*/
/*                用户态互斥锁                   */
/*----------------------------------------------*/



SEC("uprobe/pthread_mutex_lock")
int BPF_KPROBE(pthread_mutex_lock, void *__mutex) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid = pid_tgid >> 32;
    u64 now = bpf_ktime_get_ns();

    struct mutex_info *info = bpf_map_lookup_elem(&umutex_info_map, &__mutex);
    if (info) {
        if (info->acquire_time > 0) {
            // 如果 acquire_time 已经被设置，说明锁被争用
            info->contended_total += (now - info->acquire_time);
            info->count += 1;
        }
        info->acquire_time = now;
        info->last_owner = pid;
        bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
    } else {
        // 初始化 mutex_info
        struct mutex_info new_info = {
            .locked_total = 0,
            .locked_max = 0,
            .contended_total = 0,
            .count = 0,
            .last_owner = pid,
            .acquire_time = now,
            .ptr = (u64)__mutex,
        };
        bpf_get_current_comm(&new_info.last_name, sizeof(new_info.last_name));
        bpf_map_update_elem(&umutex_info_map, &__mutex, &new_info, BPF_ANY);
    }
    return 0;
}

SEC("uprobe/__pthread_mutex_trylock")
int BPF_KPROBE(__pthread_mutex_trylock, void *__mutex) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 now = bpf_ktime_get_ns();
    struct trylock_info info = {
        .__mutex = __mutex,
        .start_time = now,
    };
    bpf_map_update_elem(&trylock_map, &pid_tgid, &info, BPF_ANY);
    return 0;
}

SEC("uretprobe/__pthread_mutex_trylock")
int BPF_KRETPROBE(ret_pthread_mutex_trylock, int ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct trylock_info *try_info = bpf_map_lookup_elem(&trylock_map, &pid_tgid);
    if (!try_info) {
        return 0;
    }
    void *__mutex = try_info->__mutex;
    u64 now = bpf_ktime_get_ns();
    if (ret == 0) {
        struct mutex_info *info = bpf_map_lookup_elem(&umutex_info_map, &__mutex);
        if (info) {
            if (info->acquire_time > 0) {
                // 如果 acquire_time 已经被设置，说明锁被争用
                info->contended_total += (now - info->acquire_time);
                info->count += 1;
            }
            info->acquire_time = now;
            info->last_owner = pid_tgid >> 32;
            bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
        } else {
            // 初始化 mutex_info
            struct mutex_info new_info = {
                .locked_total = 0,
                .locked_max = 0,
                .contended_total = 0,
                .count = 0,
                .last_owner = pid_tgid >> 32,
                .acquire_time = now,
                .ptr = (u64)__mutex,
            };
            bpf_get_current_comm(&new_info.last_name, sizeof(new_info.last_name));
            bpf_map_update_elem(&umutex_info_map, &__mutex, &new_info, BPF_ANY);
        }
    }
    bpf_map_delete_elem(&trylock_map, &pid_tgid);
    return 0;
}

SEC("uprobe/pthread_mutex_unlock")
int BPF_KPROBE(pthread_mutex_unlock, void *__mutex){
    u64 now = bpf_ktime_get_ns();
    struct mutex_info *info = bpf_map_lookup_elem(&umutex_info_map, &__mutex);
    if (info) {
        u64 locked_time = now - info->acquire_time;
        info->locked_total += locked_time;
        if (locked_time > info->locked_max) {
            info->locked_max = locked_time;
        }
        info->acquire_time = 0;
    }
    return 0;
}

