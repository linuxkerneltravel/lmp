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
    struct mu_ctrl *mu_ctrl = bpf_map_lookup_elem(&mu_ctrl_map, &ctrl_key);
    return (mu_ctrl && mu_ctrl->mu_func) ? mu_ctrl : NULL;
}

static inline void update_mutex_info(struct mutex_info *info, u64 ts, pid_t pid) {
    info->acquire_time = ts;
    info->last_owner = pid;
    bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
}

static inline void init_mutex_info(struct mutex_info *info, u64 lock_addr, u64 ts, pid_t pid) {
    info->locked_total = 0;
    info->locked_max = 0;
    info->contended_total = 0;
    info->count = 0;
    info->last_owner = pid;
    info->acquire_time = ts;
    info->ptr = lock_addr;
    __builtin_memset(info->last_name, 0, sizeof(info->last_name));
    bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
}

SEC("kprobe/mutex_lock")
int BPF_KPROBE(trace_mutex_lock, struct mutex *lock) {
    struct mu_ctrl *mu_ctrl = get_mu_ctrl();
    if (!mu_ctrl) {
        return 0;
    }
    u64 lock_addr = (u64)lock;
    u64 ts = bpf_ktime_get_ns();
    struct mutex_info *info = bpf_map_lookup_elem(&kmutex_info_map, &lock_addr);

    if (info) {
        info->acquire_time = ts;
    } else {
        struct mutex_info new_info;
        init_mutex_info(&new_info, lock_addr, ts, 0);
        bpf_map_update_elem(&kmutex_info_map, &lock_addr, &new_info, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/mutex_trylock")
int BPF_KPROBE(trace_mutex_trylock, struct mutex *lock) {
    struct mu_ctrl *mu_ctrl = get_mu_ctrl();
    if (!mu_ctrl) {
        return 0;
    }
    int ret = PT_REGS_RC(ctx);
    if (ret != 0) {
        u64 lock_addr = (u64)lock;
        u64 ts = bpf_ktime_get_ns();
        struct mutex_info *info = bpf_map_lookup_elem(&kmutex_info_map, &lock_addr);

        if (info) {
            info->acquire_time = ts;
        } else {
            struct mutex_info new_info;
            init_mutex_info(&new_info, lock_addr, ts, 0);
            bpf_map_update_elem(&kmutex_info_map, &lock_addr, &new_info, BPF_ANY);
        }
    }

    return 0;
}

SEC("kprobe/__mutex_lock_slowpath")
int BPF_KPROBE(trace_mutex_lock_slowpath, struct mutex *lock) {
    struct mu_ctrl *mu_ctrl = get_mu_ctrl();
    if (!mu_ctrl) {
        return 0;
    }
    if (!mu_ctrl) return 0;

    u64 lock_addr = (u64)lock;
    u64 ts = bpf_ktime_get_ns();
    struct mutex_contention_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    pid_t pid = bpf_get_current_pid_tgid();
    struct task_struct *owner_task, *contender_task;
    long owner;

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
        info->contended_total += (contention_start - info->acquire_time);
        info->count++;
    } else {
        struct mutex_info new_info;
        init_mutex_info(&new_info, lock_addr, ts, 0);
        new_info.count = 1;
        bpf_map_update_elem(&kmutex_info_map, &lock_addr, &new_info, BPF_ANY);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/mutex_unlock")
int BPF_KPROBE(trace_mutex_unlock, struct mutex *lock) {
    struct mu_ctrl *mu_ctrl = get_mu_ctrl();
    if (!mu_ctrl) {
        return 0;
    }
    u64 lock_addr = (u64)lock;
    u64 ts = bpf_ktime_get_ns();
    pid_t pid = bpf_get_current_pid_tgid();
    struct mutex_info *info = bpf_map_lookup_elem(&kmutex_info_map, &lock_addr);

    if (info) {
        u64 held_time = ts - info->acquire_time;
        info->locked_total += held_time;
        if (held_time > info->locked_max) {
            info->locked_max = held_time;
        }
        info->last_owner = pid;
        bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
    }

    return 0;
}

/*----------------------------------------------*/
/*                用户态互斥锁                   */
/*----------------------------------------------*/

static inline void handle_user_mutex_lock(void *__mutex, u64 now, pid_t pid) {
    struct mutex_info *info = bpf_map_lookup_elem(&umutex_info_map, &__mutex);
    if (info) {
        if (info->acquire_time > 0) {
            info->contended_total += (now - info->acquire_time);
            info->count++;
        }
        update_mutex_info(info, now, pid);
    } else {
        struct mutex_info new_info;
        init_mutex_info(&new_info, (u64)__mutex, now, pid);
        bpf_map_update_elem(&umutex_info_map, &__mutex, &new_info, BPF_ANY);
    }
}

SEC("uprobe/pthread_mutex_lock")
int BPF_KPROBE(pthread_mutex_lock, void *__mutex) {
    struct mu_ctrl *mu_ctrl = get_mu_ctrl();
    if (!mu_ctrl) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    handle_user_mutex_lock(__mutex, now, pid);
    return 0;
}

SEC("uprobe/__pthread_mutex_trylock")
int BPF_KPROBE(__pthread_mutex_trylock, void *__mutex) {
    struct mu_ctrl *mu_ctrl = get_mu_ctrl();
    if (!mu_ctrl) {
        return 0;
    }
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
    struct mu_ctrl *mu_ctrl = get_mu_ctrl();
    if (!mu_ctrl) {
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct trylock_info *try_info = bpf_map_lookup_elem(&trylock_map, &pid_tgid);
    if (!try_info) return 0;

    if (ret == 0) {
        handle_user_mutex_lock(try_info->__mutex, try_info->start_time, pid_tgid >> 32);
    }
    bpf_map_delete_elem(&trylock_map, &pid_tgid);
    return 0;
}

SEC("uprobe/pthread_mutex_unlock")
int BPF_KPROBE(pthread_mutex_unlock, void *__mutex) {
    struct mu_ctrl *mu_ctrl = get_mu_ctrl();
    if (!mu_ctrl) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct mutex_info *info = bpf_map_lookup_elem(&umutex_info_map, &__mutex);
    if (info) {
        u64 held_time = now - info->acquire_time;
        info->locked_total += held_time;
        if (held_time > info->locked_max) {
            info->locked_max = held_time;
        }
        info->last_owner = pid;
        bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
    }
    return 0;
}
