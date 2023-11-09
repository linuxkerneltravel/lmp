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
// 内核态ebpf的内存模块代码
#include <linux/sched.h>

typedef struct {
    u32 pid;
    int32_t ksid, usid;
} psid;

typedef struct {
    char str[TASK_COMM_LEN];
} comm;

BPF_HASH(psid_count, psid, u64);
BPF_STACK_TRACE(stack_trace, STACK_STORAGE_SIZE);
BPF_HASH(pid_tgid, u32, u32);
BPF_HASH(pid_comm, u32, comm);

typedef struct
{
    __u64 addr;
    __u32 pid, o;
} piddr; // mem info key

typedef struct
{
    __u64 size;
    __u32 usid, o;
} mem_info; // mem info with stack

BPF_HASH(pid_size, u32, u64);
BPF_HASH(piddr_meminfo, piddr, mem_info);

int malloc_enter(struct pt_regs *ctx)
{
    u64 size = PT_REGS_PARM1(ctx) >> 10;
    if(!size) return -1;
    // record data
    u64 pt = bpf_get_current_pid_tgid();
    u32 pid = pt >> 32;
    u32 tgid = pt;
    pid_tgid.update(&pid, &tgid);
    comm *p = pid_comm.lookup(&pid);
    if (!p)
    {
        comm name;
        bpf_get_current_comm(&name, TASK_COMM_LEN);
        pid_comm.update(&pid, &name);
    }

    // record size
    return pid_size.update(&pid, &size);
}

int malloc_exit(struct pt_regs *ctx)
{
    // get size
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *size = pid_size.lookup(&pid);
    if(!size) return -1;

    // record stack count
    psid apsid = {
        .pid = pid,
        .usid = USER_STACK_GET,
        .ksid = -1,
    };
    u64 *count = psid_count.lookup(&apsid);
    if (!count)
        psid_count.update(&apsid, size);
    else (*count) += *size;

    // record pid_addr-info
    u64 addr = PT_REGS_RC(ctx);
    piddr a = {
        .addr = addr, 
        .pid = pid,
        .o = 0,
    };
    mem_info info = {
        .size = *size, 
        .usid = apsid.usid,
        .o = 0,
    };
    piddr_meminfo.update(&a, &info);

    // delete pid-size
    return pid_size.delete(&pid);
}

int free_enter(struct pt_regs *ctx)
{
    u64 addr = PT_REGS_PARM1(ctx);
    // get freeing size
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    piddr a = {addr, pid};
    mem_info *info = piddr_meminfo.lookup(&a);
    if(!info) return -1;

    // get allocated size
    psid apsid = {
        .ksid = -1,
        .pid = pid,
        .usid = info->usid,
    };
    u64 *size = psid_count.lookup(&apsid);
    if(!size) return -1;

    // sub the freeing size
    (*size) -= info->size;

    // del freeing addr info
    return piddr_meminfo.delete(&a);
}