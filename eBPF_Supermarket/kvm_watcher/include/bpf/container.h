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
// author: yys2020haha@163.com
//
// Kernel space BPF program used for counting container sys_entry/sys_exit info.

#ifndef __CONTAINER_H
#define __CONTAINER_H

#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#define MAX_NODENAME_LEN 64
struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
}time_info SEC(".maps");

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
}id SEC(".maps");

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value,struct container_id);   
}container_id_map SEC(".maps");


static int trace_container_sys_entry(struct trace_event_raw_sys_enter *args){
    u64 st = bpf_ktime_get_ns();
    pid_t pid = bpf_get_current_pid_tgid();
    u64 syscall_id = (u64)args->id; 
    bpf_map_update_elem(&time_info,&pid,&st,BPF_ANY);
    bpf_map_update_elem(&id,&pid,&syscall_id,BPF_ANY);
    return 0;
}
static int trace_container_sys_exit(struct trace_event_raw_sys_exit *args,void *rb,struct common_event *e){
    u64 exit_time = bpf_ktime_get_ns();
    pid_t pid = bpf_get_current_pid_tgid();
    u64 delay,start_time,syscallid;
    u64 *st = bpf_map_lookup_elem(&time_info,&pid);
    if( st !=0){
        start_time = *st;
		delay = (exit_time - start_time)/1000;
		bpf_map_delete_elem(&time_info, &pid);
	}else{ 
		return 0;
	}
    u64 *sc_id = bpf_map_lookup_elem(&id,&pid);
    if( sc_id != 0){
        syscallid = *sc_id;
		bpf_map_delete_elem(&id, &pid);
	}else{ 
		return 0;
	}
    const void *contain_id = bpf_map_lookup_elem(&container_id_map,&pid);
    if(contain_id != NULL){
        bpf_printk("hostname=%s\n",contain_id);
    }else{
        return 0;
    }
    RESERVE_RINGBUF_ENTRY(rb, e);
    e->syscall_data.delay = delay;
    bpf_get_current_comm(&e->syscall_data.comm, sizeof(e->syscall_data.comm));
    e->syscall_data.pid = pid;
    bpf_probe_read_kernel_str(&(e->syscall_data.container_id),sizeof(e->syscall_data.container_id),contain_id);
    e->syscall_data.syscall_id = syscallid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

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
#endif /* __CONTAINER_H */
