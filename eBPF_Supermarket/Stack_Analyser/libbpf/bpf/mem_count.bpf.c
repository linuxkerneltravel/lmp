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

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "stack_analyzer.h"

BPF_HASH(psid_count, psid, u64);
BPF_STACK_TRACE(stack_trace);
BPF_HASH(pid_tgid, u32, u32);
BPF_HASH(pid_comm, u32, comm);

BPF_HASH(pid_size, u32, u64);
BPF_HASH(piddr_meminfo, piddr, mem_info);

const char LICENSE[] SEC("license") = "GPL";

char u /*user stack flag*/, k /*kernel stack flag*/;
int apid;

SEC("uprobe/malloc")
int BPF_KPROBE(malloc_enter, size_t size)
{
    // bpf_printk("malloc_enter");
    // record data
    if (!size)
        return 0;
    u64 pt = bpf_get_current_pid_tgid();
    u32 pid = pt >> 32;
    u32 tgid = pt;
    bpf_map_update_elem(&pid_tgid, &pid, &tgid, BPF_ANY);
    comm *p = bpf_map_lookup_elem(&pid_comm, &pid);
    if (!p)
    {
        comm name;
        bpf_get_current_comm(&name, COMM_LEN);
        bpf_map_update_elem(&pid_comm, &pid, &name, BPF_NOEXIST);
    }

    // record size
    return bpf_map_update_elem(&pid_size, &pid, &size, BPF_ANY);
}

SEC("uretprobe/malloc")
int BPF_KRETPROBE(malloc_exit)
{
    u64 addr = PT_REGS_RC(ctx);
    if (!addr)
        return 0;
    // bpf_printk("malloc_exit");
    // get size
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *size = bpf_map_lookup_elem(&pid_size, &pid);
    if (!size)
        return -1;

    // record stack count
    psid apsid = {
        .pid = pid,
        .usid = u ? USER_STACK : -1,
        .ksid = -1,
    };
    u64 *count = bpf_map_lookup_elem(&psid_count, &apsid);
    if (!count)
        bpf_map_update_elem(&psid_count, &apsid, size, BPF_NOEXIST);
    else
        (*count) += *size;

    // record pid_addr-info
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
    return bpf_map_update_elem(&piddr_meminfo, &a, &info, BPF_NOEXIST);
}

SEC("uprobe/free")
int BPF_KPROBE(free_enter, u64 addr)
{
    // bpf_printk("free_enter");
    // get freeing size
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    piddr a = {.addr = addr, .pid = pid, .o = 0};
    mem_info *info = bpf_map_lookup_elem(&piddr_meminfo, &a);
    if (!info)
        return -1;

    // get allocated size
    psid apsid = {
        .ksid = -1,
        .pid = pid,
        .usid = info->usid,
    };
    u64 *size = bpf_map_lookup_elem(&psid_count, &apsid);
    if (!size)
        return -1;

    // sub the freeing size
    (*size) -= info->size;

    // del freeing addr info
    return bpf_map_delete_elem(&piddr_meminfo, &a);
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int mmap_enter(struct trace_event_raw_sys_enter *ctx)
{
    // bpf_printk("mmap_enter");
    u64 pt = bpf_get_current_pid_tgid();
    u32 pid = pt >> 32;
    if((apid >= 0 && pid != apid) || !pid)
        return 0;

    u64 size = (size_t)ctx->args[1];
    if (!size)
        return 0;
    
    // record data
    u32 tgid = pt;
    bpf_map_update_elem(&pid_tgid, &pid, &tgid, BPF_ANY);
    comm *p = bpf_map_lookup_elem(&pid_comm, &pid);
    if (!p)
    {
        comm name;
        bpf_get_current_comm(&name, COMM_LEN);
        bpf_map_update_elem(&pid_comm, &pid, &name, BPF_NOEXIST);
    }

    // record size
    return bpf_map_update_elem(&pid_size, &pid, &size, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int mmap_exit(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if((apid >= 0 && pid != apid) || !pid)
        return 0;

    u64 addr = ctx->args[0];
    if (addr == (void*)(-1))
        return 0;

    bpf_printk("%d", __LINE__);

    // get size
    u64 *size = bpf_map_lookup_elem(&pid_size, &pid);
    if (!size)
        return -1;

    bpf_printk("%d", __LINE__);
    // record stack count
    psid apsid = {
        .pid = pid,
        .usid = u ? USER_STACK : -1,
        .ksid = -1,
    };
    u64 *count = bpf_map_lookup_elem(&psid_count, &apsid);
    if (!count)
        bpf_map_update_elem(&psid_count, &apsid, size, BPF_NOEXIST);
    else
        (*count) += *size;

    // record pid_addr-info
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
    return bpf_map_update_elem(&piddr_meminfo, &a, &info, BPF_NOEXIST);
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int munmap_enter(struct trace_event_raw_sys_enter *ctx)
{
    // bpf_printk("munmap_enter");
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if((apid >= 0 && pid != apid) || !pid)
        return 0;

    piddr a = {.addr = (u64)ctx->args[0], .pid = pid, .o = 0};
    mem_info *info = bpf_map_lookup_elem(&piddr_meminfo, &a);
    if (!info)
        return -1;

    // get allocated size
    psid apsid = {
        .ksid = -1,
        .pid = pid,
        .usid = info->usid,
    };
    u64 *size = bpf_map_lookup_elem(&psid_count, &apsid);
    if (!size)
        return -1;

    // sub the freeing size
    u64 unsize = (u64)ctx->args[1];
    if(unsize >= *size) *size = 0;
    else (*size) -= unsize;

    // del freeing addr info
    return bpf_map_delete_elem(&piddr_meminfo, &a);
}