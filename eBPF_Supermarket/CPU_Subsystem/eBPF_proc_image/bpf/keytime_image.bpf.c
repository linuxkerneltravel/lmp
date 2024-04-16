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
#include "keytime_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int max_args = DEFAULT_MAXARGS;

const volatile pid_t ignore_tgid = -1;
const int key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct kt_ctrl);
} kt_ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, struct child_info);
} child SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, bool);
} pthread_create_enable SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, unsigned int);
} proc_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 10240);
} keytime_rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	struct kt_ctrl *kt_ctrl;
	kt_ctrl = bpf_map_lookup_elem(&kt_ctrl_map,&key);
	if(!kt_ctrl || !kt_ctrl->kt_func)
		return 0;
    
    int pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;
    
    if((kt_ctrl->enable_myproc || tgid!=ignore_tgid) && ((kt_ctrl->target_tgid==-1 && kt_ctrl->target_pid==-1) || 
       (kt_ctrl->target_tgid!=-1 && tgid==kt_ctrl->target_tgid) || (kt_ctrl->target_pid!=-1 && pid==kt_ctrl->target_pid))){
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
        if(kt_ctrl->target_tgid != -1)	event->tgid = tgid;
		else	event->tgid = -1;
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
	struct kt_ctrl *kt_ctrl;
	kt_ctrl = bpf_map_lookup_elem(&kt_ctrl_map,&key);
	if(!kt_ctrl || !kt_ctrl->kt_func)
		return 0;
    
    int pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if((kt_ctrl->enable_myproc || tgid!=ignore_tgid) && ((kt_ctrl->target_tgid==-1 && kt_ctrl->target_pid==-1) || 
       (kt_ctrl->target_tgid!=-1 && tgid==kt_ctrl->target_tgid) || (kt_ctrl->target_pid!=-1 && pid==kt_ctrl->target_pid))){
        struct keytime_event* event;
        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;

        event->type = 2;
        event->pid = pid;
        if(kt_ctrl->target_tgid != -1)	event->tgid = tgid;
		else	event->tgid = -1;
        event->enable_char_info = false;
        event->info_count = 1;
        event->info[0] = ctx->ret;

        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

// 记录 fork 子进程的开始时间，并输出
SEC("uretprobe/fork")
int BPF_KRETPROBE(fork_exit,int ret)
{
	struct kt_ctrl *kt_ctrl;
	kt_ctrl = bpf_map_lookup_elem(&kt_ctrl_map,&key);
	if(!kt_ctrl || !kt_ctrl->kt_func)
		return 0;
    
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;
    
    // 判断是否为父进程触发
    if((kt_ctrl->enable_myproc || tgid!=ignore_tgid) && ret!=0 && ((kt_ctrl->target_pid ==-1 && kt_ctrl->target_tgid==-1) || 
       (kt_ctrl->target_tgid!=-1 && tgid==kt_ctrl->target_tgid) || (kt_ctrl->target_pid!=-1 && pid==kt_ctrl->target_pid))){
        pid_t child_pid = ret;
        child_create(4,child_pid,pid,&child,&keytime_rb,tgid,kt_ctrl->target_tgid);
    }

	return 0;
}

// 记录 vfork 子进程的开始时间，并输出
SEC("uretprobe/vfork")
int BPF_KRETPROBE(vfork_exit,int ret)
{
	struct kt_ctrl *kt_ctrl;
	kt_ctrl = bpf_map_lookup_elem(&kt_ctrl_map,&key);
	if(!kt_ctrl || !kt_ctrl->kt_func)
		return 0;
    
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    pid_t ppid = BPF_CORE_READ(current,real_parent,pid);
    int ptgid = BPF_CORE_READ(current,real_parent,tgid);
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if((kt_ctrl->enable_myproc || tgid!=ignore_tgid) && ((kt_ctrl->target_pid==-1 && kt_ctrl->target_tgid==-1) || 
       (kt_ctrl->target_pid!=-1 && ppid==kt_ctrl->target_pid)) || (kt_ctrl->target_tgid!=-1 && ptgid==kt_ctrl->target_tgid)){
        pid_t child_pid = BPF_CORE_READ(current,pid);
        child_create(6,child_pid,ppid,&child,&keytime_rb,ptgid,kt_ctrl->target_tgid);
    }

	return 0;
}

SEC("uprobe/pthread_create")
int BPF_KPROBE(pthread_create_enter)
{
    struct kt_ctrl *kt_ctrl;
	kt_ctrl = bpf_map_lookup_elem(&kt_ctrl_map,&key);
	if(!kt_ctrl || !kt_ctrl->kt_func)
		return 0;
    
    int current = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if((kt_ctrl->enable_myproc || tgid!=ignore_tgid) && ((kt_ctrl->target_tgid==-1 && kt_ctrl->target_pid==-1) || 
    (kt_ctrl->target_tgid!=-1 && tgid==kt_ctrl->target_tgid) || (kt_ctrl->target_pid!=-1 && current==kt_ctrl->target_pid))){
        bool pthread_create_flag = true;
        bpf_map_update_elem(&pthread_create_enable, &current, &pthread_create_flag, BPF_ANY);
    }
    
	return 0;
}

SEC("uretprobe/pthread_create")
int BPF_KRETPROBE(pthread_create_exit,int ret)
{
    struct kt_ctrl *kt_ctrl;
	kt_ctrl = bpf_map_lookup_elem(&kt_ctrl_map,&key);
	if(!kt_ctrl || !kt_ctrl->kt_func)
		return 0;
    
    int current = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;
    
    if((kt_ctrl->enable_myproc || tgid!=ignore_tgid) && ((kt_ctrl->target_tgid==-1 && kt_ctrl->target_pid==-1) || 
    (kt_ctrl->target_tgid!=-1 && tgid==kt_ctrl->target_tgid) || (kt_ctrl->target_pid!=-1 && current==kt_ctrl->target_pid))){
        bpf_map_delete_elem(&pthread_create_enable, &current);
    }

	return 0;
}

// 记录 pthread_create 新线程的开始时间，并输出
SEC("tracepoint/syscalls/sys_exit_clone3")
int tracepoint__syscalls__sys_exit_clone3(struct trace_event_raw_sys_exit* ctx)
{
    struct kt_ctrl *kt_ctrl;
	kt_ctrl = bpf_map_lookup_elem(&kt_ctrl_map,&key);
	if(!kt_ctrl || !kt_ctrl->kt_func)
		return 0;
    
    pid_t current = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if((kt_ctrl->enable_myproc || tgid!=ignore_tgid) && ((kt_ctrl->target_tgid==-1 && kt_ctrl->target_pid==-1) || 
       (kt_ctrl->target_tgid!=-1 && tgid==kt_ctrl->target_tgid) || (kt_ctrl->target_pid!=-1 && current==kt_ctrl->target_pid))){
        // 判断是否是pthread_create函数触发的clone3系统调用
        bool *pthread_create_flag;
        pthread_create_flag = bpf_map_lookup_elem(&pthread_create_enable, &current);
        if(pthread_create_flag && *pthread_create_flag){
            pid_t new_thread = ctx->ret;
            // 排除clone3错误返回的情况
            if(new_thread <= 0)	return 0;

            child_create(8,new_thread,current,&child,&keytime_rb,tgid,kt_ctrl->target_tgid);
        }
    }

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int tracepoint__syscalls__sys_enter_exit_group(struct trace_event_raw_sys_enter* ctx)
{
    struct kt_ctrl *kt_ctrl;
	kt_ctrl = bpf_map_lookup_elem(&kt_ctrl_map,&key);
	if(!kt_ctrl || !kt_ctrl->kt_func)
		return 0;
    
    int pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if((kt_ctrl->enable_myproc || tgid!=ignore_tgid) && ((kt_ctrl->target_tgid==-1 && kt_ctrl->target_pid==-1) || 
       (kt_ctrl->target_tgid!=-1 && tgid==kt_ctrl->target_tgid) || (kt_ctrl->target_pid!=-1 && pid==kt_ctrl->target_pid))){
        // 记录进程退出信息
        struct keytime_event* event;
        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;
        
        event->type = 3;
        event->pid = pid;
        if(kt_ctrl->target_tgid != -1)	event->tgid = tgid;
		else	event->tgid = -1;
        event->enable_char_info = false;
        event->info_count = 1;
        event->info[0] = ctx->args[0];

        bpf_ringbuf_submit(event, 0);
    }

    // 记录 fork 和 vfork 子进程的退出时间，并输出到 ringbuf 中
    child_exit(&child,&keytime_rb);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int tracepoint__syscalls__sys_enter_exit(struct trace_event_raw_sys_enter* ctx)
{
    struct kt_ctrl *kt_ctrl;
	kt_ctrl = bpf_map_lookup_elem(&kt_ctrl_map,&key);
	if(!kt_ctrl || !kt_ctrl->kt_func)
		return 0;
    
    int pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if((kt_ctrl->enable_myproc || tgid!=ignore_tgid) && ((kt_ctrl->target_tgid==-1 && kt_ctrl->target_pid==-1) || 
       (kt_ctrl->target_tgid!=-1 && tgid==kt_ctrl->target_tgid) || (kt_ctrl->target_pid!=-1 && pid==kt_ctrl->target_pid))){
        // 记录进程退出信息
        struct keytime_event* event;
        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;
        
        event->type = 3;
        event->pid = pid;
        if(kt_ctrl->target_tgid != -1)	event->tgid = tgid;
		else	event->tgid = -1;
        event->enable_char_info = false;
        event->info_count = 1;
        event->info[0] = ctx->args[0];

        bpf_ringbuf_submit(event, 0);
    }

    // 记录 pthread_create 新线程的退出时间，并输出
    child_exit(&child,&keytime_rb);

    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    struct kt_ctrl *kt_ctrl;
	kt_ctrl = bpf_map_lookup_elem(&kt_ctrl_map,&key);
	if(!kt_ctrl || !kt_ctrl->kt_cpu_func)
		return 0;

    pid_t next_pid = BPF_CORE_READ(next,pid);
    int next_tgid = BPF_CORE_READ(next,tgid);
	pid_t prev_pid = BPF_CORE_READ(prev,pid);
    int prev_tgid = BPF_CORE_READ(prev,tgid);
	int cpu_id = bpf_get_smp_processor_id();

    // 记录 prev 进程的下CPU时的信息
    if((kt_ctrl->enable_myproc || prev_tgid!=ignore_tgid) && prev_pid!=0 && ((kt_ctrl->target_tgid==-1 && kt_ctrl->target_pid==-1) || 
       (kt_ctrl->target_tgid!=-1 && prev_tgid==kt_ctrl->target_tgid) || (kt_ctrl->target_pid!=-1 && prev_pid==kt_ctrl->target_pid))){
        struct offcpu_event* event;

        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;

        event->type = 11;
        event->pid = prev_pid;
        if(kt_ctrl->target_tgid != -1)	event->tgid = prev_tgid;
		else	event->tgid = -1;
        event->offcpu_time = bpf_ktime_get_ns();
        event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

        bpf_ringbuf_submit(event, 0);
    }

    // 记录 next 进程上CPU时的信息
    if((kt_ctrl->enable_myproc || next_tgid!=ignore_tgid) && next_pid!=0 && ((kt_ctrl->target_tgid==-1 && kt_ctrl->target_pid==-1) || 
       (kt_ctrl->target_tgid!=-1 && next_tgid==kt_ctrl->target_tgid) || (kt_ctrl->target_pid!=-1 && next_pid==kt_ctrl->target_pid))){
        struct keytime_event* event;

        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;

        event->type = 10;
        event->pid = next_pid;
        if(kt_ctrl->target_tgid != -1)	event->tgid = next_tgid;
		else	event->tgid = -1;
        event->enable_char_info = false;
        event->info_count = 1;
        event->info[0] = bpf_ktime_get_ns();

        bpf_ringbuf_submit(event, 0);
    }

    return 0;

}

/* 暂时舍弃，后面会继续开发用作记录进程的状态变化
// 记录进程 onCPU 和 offCPU 的相关信息
SEC("kprobe/finish_task_switch.isra.0")
int kprobe__finish_task_switch(struct pt_regs *ctx)
{
    struct task_struct *prev = (struct task_struct *)PT_REGS_PARM1(ctx);
	pid_t prev_pid = BPF_CORE_READ(prev,pid);
	int prev_tgid = BPF_CORE_READ(prev,tgid);
	struct task_struct *next = (struct task_struct *)bpf_get_current_task();
	pid_t next_pid = BPF_CORE_READ(next,pid);
	int next_tgid = BPF_CORE_READ(next,tgid);
	
	// 记录 prev 进程的 offCPU 信息
    if(prev_tgid!=ignore_tgid && prev_pid!=0 && (prev_pid==target_pid || target_pid==-1)){
        unsigned int * old_state;
        unsigned int new_state = BPF_CORE_READ(prev,__state);
        struct keytime_event* event;

        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;

        old_state = bpf_map_lookup_elem(&proc_state, &prev_pid);
        if(old_state){
            event->info_count = 2;
            event->info[0] = *old_state;
            event->info[1] = new_state;
            bpf_map_update_elem(&proc_state, &prev_pid, &new_state, BPF_ANY);
        } else {
            event->info_count = 1;
            event->info[0] = new_state;
            bpf_map_update_elem(&proc_state, &prev_pid, &new_state, BPF_ANY);
        }
        event->type = 11;
        event->pid = prev_pid;
        event->enable_char_info = false;

        bpf_ringbuf_submit(event, 0);
    }

    // 记录 next 进程的 onCPU 信息
    if(next_tgid!=ignore_tgid && next_pid!=0 && (next_pid==target_pid || target_pid==-1)){
        unsigned int * old_state;
        unsigned int new_state = BPF_CORE_READ(next,__state);
        struct keytime_event* event;

        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;

        old_state = bpf_map_lookup_elem(&proc_state, &next_pid);
        if(old_state){
            event->info_count = 2;
            event->info[0] = *old_state;
            event->info[1] = new_state;
            bpf_map_update_elem(&proc_state, &next_pid, &new_state, BPF_ANY);
        } else {
            event->info_count = 1;
            event->info[0] = new_state;
            bpf_map_update_elem(&proc_state, &next_pid, &new_state, BPF_ANY);
        }
        event->type = 10;
        event->pid = next_pid;
        event->enable_char_info = false;

        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

// 记录唤醒进程的相关信息
SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    pid_t cur_pid = BPF_CORE_READ(p,pid);
	int cur_tgid = BPF_CORE_READ(p,tgid);

    if(cur_tgid!=ignore_tgid && cur_pid!=0 && (cur_pid==target_pid || target_pid==-1)){
        unsigned int * old_state;
        unsigned int new_state = BPF_CORE_READ(p,__state);
        struct keytime_event* event;

        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;

        old_state = bpf_map_lookup_elem(&proc_state, &cur_pid);
        if(old_state){
            event->info_count = 2;
            event->info[0] = *old_state;
            event->info[1] = new_state;
            bpf_map_update_elem(&proc_state, &cur_pid, &new_state, BPF_ANY);
        } else {
            event->info_count = 1;
            event->info[0] = new_state;
            bpf_map_update_elem(&proc_state, &cur_pid, &new_state, BPF_ANY);
        }
        event->type = 12;
        event->pid = cur_pid;
        event->enable_char_info = false;

        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
    pid_t cur_pid = BPF_CORE_READ(p,pid);
	int cur_tgid = BPF_CORE_READ(p,tgid);

    if(cur_tgid!=ignore_tgid && cur_pid!=0 && (cur_pid==target_pid || target_pid==-1)){
        unsigned int * old_state;
        unsigned int new_state = BPF_CORE_READ(p,__state);
        struct keytime_event* event;

        event = bpf_ringbuf_reserve(&keytime_rb, sizeof(*event), 0);
        if(!event)
            return 0;

        old_state = bpf_map_lookup_elem(&proc_state, &cur_pid);
        if(old_state){
            event->info_count = 2;
            event->info[0] = *old_state;
            event->info[1] = new_state;
            bpf_map_update_elem(&proc_state, &cur_pid, &new_state, BPF_ANY);
        } else {
            event->info_count = 1;
            event->info[0] = new_state;
            bpf_map_update_elem(&proc_state, &cur_pid, &new_state, BPF_ANY);
        }
        event->type = 12;
        event->pid = cur_pid;
        event->enable_char_info = false;

        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}
*/