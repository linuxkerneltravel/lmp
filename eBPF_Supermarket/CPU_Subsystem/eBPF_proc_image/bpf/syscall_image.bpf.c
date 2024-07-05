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
// eBPF kernel-mode code that collects process syscalls

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define MAX_NODENAME_LEN 64
const volatile pid_t ignore_tgid = -1;
const volatile char hostname[MAX_NODENAME_LEN] = "";
const int key = 0;
pid_t pre_target_pid = -1;//上一个监测的进程；
int pre_target_tgid = -1;//上一个监测的进程组；

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct sc_ctrl);
} sc_ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value,struct syscall_seq);
} proc_syscall SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 10240);
} syscall_rb SEC(".maps");

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value,struct container_id);   
}container_id_map SEC(".maps");

struct container_id{
    char container_id[20];
};

struct data_t {
    char nodename[MAX_NODENAME_LEN];
};

static bool is_container_task(const volatile char hostname[MAX_NODENAME_LEN]){
    struct task_struct *task;
    struct nsproxy *ns;
    struct uts_namespace *uts;
    struct data_t data = {};
    // 获取当前任务的 task_struct
    task = (struct task_struct *)bpf_get_current_task();
    // 获取 nsproxy
    bpf_probe_read_kernel(&ns, sizeof(ns), &task->nsproxy);
    if (!ns) {
        return false;
    }
    // 获取 uts_namespace
    bpf_probe_read_kernel(&uts, sizeof(uts), &ns->uts_ns);
    if (!uts) {
        return false;
    }
    // 读取主机名
    bpf_probe_read_kernel_str(&data.nodename, sizeof(data.nodename), uts->name.nodename);
    // 打印主机名
    bool is_equal = true;
    for(int i = 0;i<MAX_NODENAME_LEN;i++){
        if(data.nodename[i] != hostname[i]){
            pid_t pid = bpf_get_current_pid_tgid();
            bpf_map_update_elem(&container_id_map,&pid,&data.nodename,BPF_ANY);
            is_equal = false;
            break;
        }
        if(data.nodename[i]=='\0'||hostname[i]=='\0'){
            break;
        }
    }
    if (is_equal){
        return false;
    } else {
        return true;
    }
}
SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *args)
{
    struct sc_ctrl *sc_ctrl;
	sc_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
    if(!sc_ctrl || !sc_ctrl->sc_func)
		return 0;
    if(sc_ctrl->is_container)
        if(!is_container_task(hostname))
            return 0;
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if(sc_ctrl->enable_myproc || tgid!=ignore_tgid){
        u64 current_time = bpf_ktime_get_ns();
        struct syscall_seq * syscall_seq;

        syscall_seq = bpf_map_lookup_elem(&proc_syscall, &pid);
        if(!syscall_seq){
            struct syscall_seq syscall_seq = {};

            syscall_seq.pid = pid;
            syscall_seq.enter_time = current_time;
            syscall_seq.count = 1;
            if((sc_ctrl->target_tgid==-1 && (sc_ctrl->target_pid==-1 || pid==sc_ctrl->target_pid)) || 
               (sc_ctrl->target_tgid!=-1 && tgid == sc_ctrl->target_tgid)){
                syscall_seq.record_syscall[0] = (int)args->id;
            }
            
            bpf_map_update_elem(&proc_syscall, &pid, &syscall_seq, BPF_ANY);
        }else{
            syscall_seq->enter_time = current_time;
            if(syscall_seq->count == 0){
                if((sc_ctrl->target_tgid==-1 && (sc_ctrl->target_pid==-1 || pid==sc_ctrl->target_pid)) || (sc_ctrl->target_tgid!=-1 && tgid == sc_ctrl->target_tgid)){
                    syscall_seq->record_syscall[syscall_seq->count] = (int)args->id;
                }
                syscall_seq->count++;
            }else if (syscall_seq->count <= MAX_SYSCALL_COUNT-1 && syscall_seq->count > 0 && 
                      syscall_seq->record_syscall+syscall_seq->count <= syscall_seq->record_syscall+(MAX_SYSCALL_COUNT-1)){
                if((sc_ctrl->target_tgid==-1 && (sc_ctrl->target_pid==-1 || pid==sc_ctrl->target_pid)) || 
                    (sc_ctrl->target_tgid!=-1 && tgid == sc_ctrl->target_tgid)){
                    syscall_seq->record_syscall[syscall_seq->count] = (int)args->id;
                }
                syscall_seq->count++;
            }
        }
    }

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *args)
{
    struct sc_ctrl *sc_ctrl;
	sc_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
	if(!sc_ctrl || !sc_ctrl->sc_func)
		return 0;
    if(sc_ctrl->is_container)
        if(!is_container_task(hostname))
            return 0;
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if(sc_ctrl->enable_myproc || tgid!=ignore_tgid){
        u64 current_time = bpf_ktime_get_ns();
        long long unsigned int this_delay;
        struct syscall_seq * syscall_seq;

        syscall_seq = bpf_map_lookup_elem(&proc_syscall, &pid);
        if(!syscall_seq){
            return 0;
        }
        
        this_delay = current_time-syscall_seq->enter_time;

        if(syscall_seq->count < sc_ctrl->syscalls){
            syscall_seq->sum_delay += this_delay;
            if(this_delay > syscall_seq->max_delay)
                syscall_seq->max_delay = this_delay;
            if(syscall_seq->min_delay==0 || this_delay<syscall_seq->min_delay)
                syscall_seq->min_delay = this_delay;

            //bpf_map_update_elem(&proc_syscall, &pid, syscall_seq, BPF_ANY);
        }else{
            syscall_seq->sum_delay += this_delay;
            if(this_delay > syscall_seq->max_delay)
                syscall_seq->max_delay = this_delay;
            if(syscall_seq->min_delay==0 || this_delay<syscall_seq->min_delay)
                syscall_seq->min_delay = this_delay;
            //策略切换，首次数据不记录；
            if(sc_ctrl->target_tgid ==-1 && sc_ctrl->target_pid ==pid && sc_ctrl->target_pid != pre_target_pid){
                syscall_seq->sum_delay = 0;
                syscall_seq->count = 0;
                pre_target_pid = sc_ctrl->target_pid;//更改pre_target_pid；
                return 0;                
            }
            if(sc_ctrl->target_tgid !=-1 && sc_ctrl->target_tgid ==tgid && sc_ctrl->target_tgid != pre_target_tgid){
                syscall_seq->sum_delay = 0;
                syscall_seq->count = 0;
                pre_target_tgid = sc_ctrl->target_tgid;//更改pre_target_pid；
                return 0;                
            }
            
            if((sc_ctrl->target_tgid==-1 && (sc_ctrl->target_pid==-1 || pid==sc_ctrl->target_pid)) || 
               (sc_ctrl->target_tgid!=-1 && tgid == sc_ctrl->target_tgid)){
                syscall_seq->proc_count += syscall_seq->count;
                syscall_seq->proc_sd += syscall_seq->sum_delay;
            }

            struct syscall_seq* e;
            e = bpf_ringbuf_reserve(&syscall_rb, sizeof(*e), 0);
            if(!e)
                return 0;
            
            e->pid = pid;
            e->tgid = tgid;
            e->sum_delay = syscall_seq->sum_delay;
            e->max_delay = syscall_seq->max_delay;
            e->min_delay = syscall_seq->min_delay;
            e->count = syscall_seq->count;
            for(int i=0; i<=syscall_seq->count-1 && i<=MAX_SYSCALL_COUNT-1; i++)
                e->record_syscall[i] = syscall_seq->record_syscall[i];
            if((sc_ctrl->target_tgid==-1 && (sc_ctrl->target_pid==-1 || pid==sc_ctrl->target_pid)) || 
               (sc_ctrl->target_tgid!=-1 && tgid == sc_ctrl->target_tgid)){
                e->proc_count = syscall_seq->proc_count;
                e->proc_sd = syscall_seq->proc_sd;
            }
            
            bpf_ringbuf_submit(e, 0);

            syscall_seq->sum_delay = 0;
            syscall_seq->count = 0;
        }
    }

    return 0;
}

// 从哈希表中删除退出进程的数据，防止哈希表溢出
SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void *ctx)
{
    struct sc_ctrl *sc_ctrl;
	sc_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
	if(!sc_ctrl || !sc_ctrl->sc_func)
		return 0;
    
    struct task_struct *p = (struct task_struct *)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(p,pid);

    bpf_map_delete_elem(&proc_syscall,&pid);

    return 0;
}