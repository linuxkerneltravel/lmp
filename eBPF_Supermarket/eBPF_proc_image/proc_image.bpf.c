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
// kernel-mode code for the process image

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "include/proc_image.h"
#include "include/lifecycle_image.h"
#include "include/keytime_image.h"
#include "include/lock_image.h"
#include "include/newlife_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t target_pid = 0;
const volatile int target_cpu_id = 0;

/* lifecycle_image */ 
const volatile bool enable_cputime = false;

/* keytime_image */
const volatile bool enable_execve = false;
const volatile bool enable_exit = false;

/* lock_image */ 
const volatile bool enable_u_mutex = false;
const volatile bool enable_k_mutex = false;
const volatile bool enable_u_rwlock_rd = false;
const volatile bool enable_u_rwlock_wr = false;

/* newlife_image */
const volatile bool enable_fork = false;
const volatile bool enable_vfork = false;
const volatile bool enable_newthread = false;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/* lifecycle_image */
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    if(enable_cputime){
        record_cputime(ctx, prev, next, target_pid, target_cpu_id, &events);
    }

    return 0;
}

/* keytime_image */
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    if(enable_execve){
        record_enter_execve(ctx, target_pid, &events);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
    if(enable_execve){
        record_exit_execve(ctx, target_pid, &events);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int tracepoint__syscalls__sys_enter_exit_group(struct trace_event_raw_sys_enter* ctx)
{
	if(enable_exit){
        record_exit(ctx, target_pid, &events);
    }

    /* newlife_image，记录 fork 和 vfork 子进程的退出时间，并输出 */
    if(enable_fork || enable_vfork){
		newlife_exit(ctx,target_pid,&events);
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int tracepoint__syscalls__sys_enter_exit(struct trace_event_raw_sys_enter* ctx)
{
	if(enable_exit){
        record_exit(ctx, target_pid, &events);
    }

    /* newlife_image，// 记录 pthread_create 新线程的退出时间，并输出 */
    if(enable_newthread){
		newlife_exit(ctx,target_pid,&events);
	}

	return 0;
}

/* lock_image */
// 用户态互斥锁
SEC("uprobe/pthread_mutex_lock")
int BPF_KPROBE(pthread_mutex_lock_enter, void *__mutex)
{
    if(enable_u_mutex){
        record_lock_enter(ctx,6,1,__mutex,target_pid,&events);
    }

    return 0;
}

SEC("uretprobe/pthread_mutex_lock")
int BPF_KRETPROBE(pthread_mutex_lock_exit,int ret)
{
    if(enable_u_mutex){
        record_lock_exit(ctx,1,ret,target_pid,&events);
    }

    return 0;
}

SEC("uprobe/__pthread_mutex_trylock")
int BPF_KPROBE(__pthread_mutex_trylock_enter, void *__mutex)
{
    if(enable_u_mutex){
        record_lock_enter(ctx,6,1,__mutex,target_pid,&events);
    }

    return 0;
}

SEC("uretprobe/__pthread_mutex_trylock")
int BPF_KRETPROBE(__pthread_mutex_trylock_exit,int ret)
{
    if(enable_u_mutex){
        record_lock_exit(ctx,1,ret,target_pid,&events);
    }
    
    return 0;
}

SEC("uprobe/pthread_mutex_unlock")
int BPF_KPROBE(pthread_mutex_unlock_enter, void *__rwlock)
{
    if(enable_u_mutex){
        record_unlock_enter(1,__rwlock,target_pid);
    }
    
    return 0;
}

SEC("uretprobe/pthread_mutex_unlock")
int BPF_KRETPROBE(pthread_mutex_unlock_exit)
{
    if(enable_u_mutex){
        record_unlock_exit(ctx,1,target_pid,&events);
    }
    
    return 0;
}

// 内核态互斥锁
SEC("kprobe/mutex_lock")
int kprobe__mutex_lock(struct pt_regs *ctx)
{
    if(enable_k_mutex){
        struct mutex *lock = (struct mutex *)PT_REGS_PARM1(ctx);
        record_lock_enter(ctx,9,2,lock,target_pid,&events);
    }

    return 0;
}

SEC("kretprobe/mutex_lock")
int kretprobe__mutex_lock(struct pt_regs *ctx)
{
    if(enable_k_mutex){
        record_lock_exit(ctx,2,0,target_pid,&events);
    }

    return 0;
}

SEC("kprobe/mutex_trylock")
int kprobe__mutex_trylock(struct pt_regs *ctx)
{
    if(enable_k_mutex){
        struct mutex *lock = (struct mutex *)PT_REGS_PARM1(ctx);
        record_lock_enter(ctx,9,2,lock,target_pid,&events);
    }

    return 0;
}

SEC("kretprobe/mutex_trylock")
int kretprobe__mutex_trylock(struct pt_regs *ctx)
{
    if(enable_k_mutex){
        record_lock_exit(ctx,2,0,target_pid,&events);
    }

    return 0;
}

SEC("kprobe/mutex_unlock")
int kprobe__mutex_unlock(struct pt_regs *ctx)
{
    if(enable_k_mutex){
        struct mutex *lock = (struct mutex *)PT_REGS_PARM1(ctx);
        record_unlock_enter(2,lock,target_pid);
    }

    return 0;
}

SEC("kretprobe/mutex_unlock")
int kretprobe__mutex_unlock(struct pt_regs *ctx)
{
    if(enable_k_mutex){
        record_unlock_exit(ctx,2,target_pid,&events);
    }
    
    return 0;
}

// 用户态读写锁
SEC("uprobe/__pthread_rwlock_rdlock")
int BPF_KPROBE(__pthread_rwlock_rdlock_enter, void *__rwlock)
{
    if(enable_u_rwlock_rd){
        record_lock_enter(ctx,12,3,__rwlock,target_pid,&events);
    }

    return 0;
}

SEC("uretprobe/__pthread_rwlock_rdlock")
int BPF_KRETPROBE(__pthread_rwlock_rdlock_exit,int ret)
{
    if(enable_u_rwlock_rd){
        record_lock_exit(ctx,3,ret,target_pid,&events);
    }

    return 0;
}

SEC("uprobe/__pthread_rwlock_tryrdlock")
int BPF_KPROBE(__pthread_rwlock_tryrdlock_enter, void *__rwlock)
{
    if(enable_u_rwlock_rd){
        record_lock_enter(ctx,12,3,__rwlock,target_pid,&events);
    }
    
    return 0;
}

SEC("uretprobe/__pthread_rwlock_tryrdlock")
int BPF_KRETPROBE(__pthread_rwlock_tryrdlock_exit,int ret)
{
    if(enable_u_rwlock_rd){
        record_lock_exit(ctx,3,ret,target_pid,&events);
    }

    return 0;
}

SEC("uprobe/__pthread_rwlock_wrlock")
int BPF_KPROBE(__pthread_rwlock_wrlock_enter, void *__rwlock)
{
    if(enable_u_rwlock_wr){
        record_lock_enter(ctx,15,3,__rwlock,target_pid,&events);
    }
    
    return 0;
}

SEC("uretprobe/__pthread_rwlock_wrlock")
int BPF_KRETPROBE(__pthread_rwlock_wrlock_exit,int ret)
{
    if(enable_u_rwlock_wr){
        record_lock_exit(ctx,3,ret,target_pid,&events);
    }

    return 0;
}

SEC("uprobe/__pthread_rwlock_trywrlock")
int BPF_KPROBE(__pthread_rwlock_trywrlock_enter, void *__rwlock)
{
    if(enable_u_rwlock_wr){
        record_lock_enter(ctx,15,3,__rwlock,target_pid,&events);
    }

    return 0;
}

SEC("uretprobe/__pthread_rwlock_trywrlock")
int BPF_KRETPROBE(__pthread_rwlock_trywrlock_exit,int ret)
{
    if(enable_u_rwlock_wr){
        record_lock_exit(ctx,3,ret,target_pid,&events);
    }

    return 0;
}

SEC("uprobe/__pthread_rwlock_unlock")
int BPF_KPROBE(__pthread_rwlock_unlock_enter, void *__rwlock)
{
    if(enable_u_rwlock_rd || enable_u_rwlock_wr){
        record_unlock_enter(3,__rwlock,target_pid);
    }

    return 0;
}

SEC("uretprobe/__pthread_rwlock_unlock")
int BPF_KRETPROBE(__pthread_rwlock_unlock_exit)
{
    if(enable_u_rwlock_rd || enable_u_rwlock_wr){
        record_unlock_exit(ctx,3,target_pid,&events);
    }
    
    return 0;
}

/* newlife_image */
// 记录 fork 子进程的开始时间，并输出
SEC("uretprobe/fork")
int BPF_KRETPROBE(fork_exit,int ret)
{
	if(enable_fork){
		// 判断是否为子进程触发
		if(ret != 0)	return 0;

		pid_t child_pid = bpf_get_current_pid_tgid();
		newlife_create(ctx,18,child_pid,target_pid,&events);
	}

	return 0;
}

// 记录 vfork 子进程的开始时间，并输出
SEC("uretprobe/vfork")
int BPF_KRETPROBE(vfork_exit,int ret)
{
	if(enable_vfork){
		// 判断是否为子进程触发
		if(ret != 0)	return 0;

		pid_t child_pid = bpf_get_current_pid_tgid();
		newlife_create(ctx,20,child_pid,target_pid,&events);
	}

	return 0;
}

// 记录 pthread_create 新线程的开始时间，并输出
SEC("tracepoint/syscalls/sys_exit_clone3")
int tracepoint__syscalls__sys_exit_clone3(struct trace_event_raw_sys_exit* ctx)
{
	if(enable_newthread){
		pid_t current = bpf_get_current_pid_tgid();

		if(current == target_pid)
		{
			pid_t new_thread = ctx->ret;
			// 排除clone3错误返回的情况
			if(new_thread <= 0)	return 0;

			newlife_create(ctx,22,new_thread,target_pid,&events);
		}
	}

	return 0;
}