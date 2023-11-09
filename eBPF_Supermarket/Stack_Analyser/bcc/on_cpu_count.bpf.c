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
// author: luiyanbing@foxmail.com
//
// 内核态ebpf的cpu占用模块代码
#include <linux/sched.h>

typedef struct {
    u32 pid;
    int32_t ksid, usid;
} psid;

typedef struct {
    char str[TASK_COMM_LEN];
} comm;

BPF_HASH(pid_tgid, u32, u32);
BPF_STACK_TRACE(stack_trace, STACK_STORAGE_SIZE);
BPF_HASH(psid_count, psid, u32);
BPF_HASH(pid_comm, u32, comm);

int do_stack(void *ctx) {
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    if(!((THREAD_FILTER) && (STATE_FILTER)))
        return -1;
    
    u32 pid = curr->pid;
    u32 tgid = curr->tgid;
    pid_tgid.update(&pid, &tgid);
    comm *p = pid_comm.lookup(&pid);
    if(!p) {
        comm name;
        bpf_probe_read_kernel_str(&name, TASK_COMM_LEN, curr->comm);
        pid_comm.update(&pid, &name);
    }
    psid apsid = {
        .pid = pid,
        .ksid = KERNEL_STACK_GET,
        .usid = USER_STACK_GET,
    };
    psid_count.increment(apsid);
    return 0;
}