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
// eBPF map for the process life cycle image

#ifndef __LIFECYCLE_IMAGE_H
#define __LIFECYCLE_IMAGE_H

#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 128

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

// 以便于对0号进程进行画像（0号进程是每cpu进程）
struct proc_id{
    int pid;
    int cpu_id;
};

struct proc_oncpu{
    int oncpu_id;
    long long unsigned int oncpu_time;
};

struct proc_offcpu{
    int offcpu_id;
    long long unsigned int offcpu_time;
};

struct cpu_event{
    int flag;
    int pid;
    int n_pid;
    char comm[TASK_COMM_LEN];
    char n_comm[TASK_COMM_LEN];
    int prio;
    int n_prio;
    int oncpu_id;
    long long unsigned int oncpu_time;
    int offcpu_id;
    long long unsigned int offcpu_time;
    __s32 kstack_sz;
    stack_trace_t kstack;
};

#endif /* __LIFECYCLE_IMAGE_H */