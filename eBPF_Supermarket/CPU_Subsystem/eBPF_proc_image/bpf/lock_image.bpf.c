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
// eBPF kernel-mode code that collects holding lock information of processes

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"
#include "lock_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t ignore_tgid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct lock_ctrl);
} lock_ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct proc_flag);
	__type(value, u64);
} proc_lock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct proc_flag);
	__type(value, u64);
} proc_unlock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, int);
} locktype SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 10240);
} lock_rb SEC(".maps");

// 用户态互斥锁
SEC("uprobe/pthread_mutex_lock")
int BPF_KPROBE(pthread_mutex_lock_enter, void *__mutex)
{
    record_lock_enter(ignore_tgid,1,1,__mutex,&lock_rb,&proc_lock,&lock_ctrl_map);

    return 0;
}

SEC("uretprobe/pthread_mutex_lock")
int BPF_KRETPROBE(pthread_mutex_lock_exit,int ret)
{
    record_lock_exit(ignore_tgid,2,1,ret,&lock_rb,&proc_lock,&locktype,&lock_ctrl_map);

    return 0;
}

SEC("uprobe/__pthread_mutex_trylock")
int BPF_KPROBE(__pthread_mutex_trylock_enter, void *__mutex)
{
    record_lock_enter(ignore_tgid,1,1,__mutex,&lock_rb,&proc_lock,&lock_ctrl_map);

    return 0;
}

SEC("uretprobe/__pthread_mutex_trylock")
int BPF_KRETPROBE(__pthread_mutex_trylock_exit,int ret)
{
    record_lock_exit(ignore_tgid,2,1,ret,&lock_rb,&proc_lock,&locktype,&lock_ctrl_map);
    
    return 0;
}

SEC("uprobe/pthread_mutex_unlock")
int BPF_KPROBE(pthread_mutex_unlock_enter, void *__rwlock)
{
    record_unlock_enter(ignore_tgid,1,__rwlock,&proc_unlock,&lock_ctrl_map);
    
    return 0;
}



SEC("uretprobe/pthread_mutex_unlock")
int BPF_KRETPROBE(pthread_mutex_unlock_exit)
{
    record_unlock_exit(ignore_tgid,3,1,&lock_rb,&proc_unlock,&locktype,&lock_ctrl_map);
    
    return 0;
}

// 用户态读写锁
SEC("uprobe/__pthread_rwlock_rdlock")
int BPF_KPROBE(__pthread_rwlock_rdlock_enter, void *__rwlock)
{
    record_lock_enter(ignore_tgid,4,2,__rwlock,&lock_rb,&proc_lock,&lock_ctrl_map);

    return 0;
}

SEC("uretprobe/__pthread_rwlock_rdlock")
int BPF_KRETPROBE(__pthread_rwlock_rdlock_exit,int ret)
{
    record_lock_exit(ignore_tgid,5,2,ret,&lock_rb,&proc_lock,&locktype,&lock_ctrl_map);

    return 0;
}

SEC("uprobe/__pthread_rwlock_tryrdlock")
int BPF_KPROBE(__pthread_rwlock_tryrdlock_enter, void *__rwlock)
{
    record_lock_enter(ignore_tgid,4,2,__rwlock,&lock_rb,&proc_lock,&lock_ctrl_map);
    
    return 0;
}

SEC("uretprobe/__pthread_rwlock_tryrdlock")
int BPF_KRETPROBE(__pthread_rwlock_tryrdlock_exit,int ret)
{
    record_lock_exit(ignore_tgid,5,2,ret,&lock_rb,&proc_lock,&locktype,&lock_ctrl_map);

    return 0;
}

SEC("uprobe/__pthread_rwlock_wrlock")
int BPF_KPROBE(__pthread_rwlock_wrlock_enter, void *__rwlock)
{
    record_lock_enter(ignore_tgid,7,2,__rwlock,&lock_rb,&proc_lock,&lock_ctrl_map);
    
    return 0;
}

SEC("uretprobe/__pthread_rwlock_wrlock")
int BPF_KRETPROBE(__pthread_rwlock_wrlock_exit,int ret)
{
    record_lock_exit(ignore_tgid,8,2,ret,&lock_rb,&proc_lock,&locktype,&lock_ctrl_map);

    return 0;
}

SEC("uprobe/__pthread_rwlock_trywrlock")
int BPF_KPROBE(__pthread_rwlock_trywrlock_enter, void *__rwlock)
{
    record_lock_enter(ignore_tgid,7,2,__rwlock,&lock_rb,&proc_lock,&lock_ctrl_map);

    return 0;
}

SEC("uretprobe/__pthread_rwlock_trywrlock")
int BPF_KRETPROBE(__pthread_rwlock_trywrlock_exit,int ret)
{
    record_lock_exit(ignore_tgid,8,2,ret,&lock_rb,&proc_lock,&locktype,&lock_ctrl_map);

    return 0;
}

SEC("uprobe/__pthread_rwlock_unlock")
int BPF_KPROBE(__pthread_rwlock_unlock_enter, void *__rwlock)
{
    record_unlock_enter(ignore_tgid,2,__rwlock,&proc_unlock,&lock_ctrl_map);

    return 0;
}

SEC("uretprobe/__pthread_rwlock_unlock")
int BPF_KRETPROBE(__pthread_rwlock_unlock_exit)
{
    record_unlock_exit(ignore_tgid,0,2,&lock_rb,&proc_unlock,&locktype,&lock_ctrl_map);
    
    return 0;
}

// 用户态自旋锁
SEC("uprobe/pthread_spin_lock")
int BPF_KPROBE(pthread_spin_lock_enter, void *__spinlock)
{
    record_lock_enter(ignore_tgid,10,3,__spinlock,&lock_rb,&proc_lock,&lock_ctrl_map);

    return 0;
}

SEC("uretprobe/pthread_spin_lock")
int BPF_KRETPROBE(pthread_spin_lock_exit,int ret)
{
    record_lock_exit(ignore_tgid,11,3,ret,&lock_rb,&proc_lock,&locktype,&lock_ctrl_map);

    return 0;
}

SEC("uprobe/pthread_spin_trylock")
int BPF_KPROBE(pthread_spin_trylock_enter, void *__spinlock)
{
    record_lock_enter(ignore_tgid,10,3,__spinlock,&lock_rb,&proc_lock,&lock_ctrl_map);

    return 0;
}

SEC("uretprobe/pthread_spin_trylock")
int BPF_KRETPROBE(pthread_spin_trylock_exit,int ret)
{
    record_lock_exit(ignore_tgid,11,3,ret,&lock_rb,&proc_lock,&locktype,&lock_ctrl_map);
    
    return 0;
}

SEC("uprobe/pthread_spin_unlock")
int BPF_KPROBE(pthread_spin_unlock_enter, void *__spinlock)
{
    record_unlock_enter(ignore_tgid,3,__spinlock,&proc_unlock,&lock_ctrl_map);
    
    return 0;
}

SEC("uretprobe/pthread_spin_unlock")
int BPF_KRETPROBE(pthread_spin_unlock_exit)
{
    record_unlock_exit(ignore_tgid,12,3,&lock_rb,&proc_unlock,&locktype,&lock_ctrl_map);
    
    return 0;
}