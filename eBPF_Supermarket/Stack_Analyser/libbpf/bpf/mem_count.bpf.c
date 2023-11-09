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
#include "task.h"

BPF_HASH(psid_count, psid, u64);
BPF_STACK_TRACE(stack_trace);
BPF_HASH(pid_tgid, u32, u32);
BPF_HASH(pid_comm, u32, comm);

BPF_HASH(pid_size, u32, u64);
BPF_HASH(piddr_meminfo, piddr, mem_info);

const char LICENSE[] SEC("license") = "GPL";

bool u = false, k = false;
int apid = 0;
__u64 min = 0, max = 0;

int gen_alloc_enter(size_t size)
{
    // bpf_printk("malloc_enter");
    // record data
    if (size <= min || size > max)
        return 0;
    // u64 pt = bpf_get_current_pid_tgid();
    // u32 pid = pt >> 32;
    // u32 tgid = pt;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    u32 pid = get_task_ns_pid(curr); // also kernel pid, but attached ns pid on kernel pid, invaild!
    u32 tgid = get_task_ns_tgid(curr);
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

SEC("uprobe/malloc")
int BPF_KPROBE(malloc_enter, size_t size)
{
    return gen_alloc_enter(size);
}

SEC("uprobe/calloc")
int BPF_KPROBE(calloc_enter, size_t nmemb, size_t size)
{
    return gen_alloc_enter(nmemb * size);
}

SEC("uprobe/mmap")
int BPF_KPROBE(mmap_enter)
{
    size_t size = PT_REGS_PARM2(ctx);
    return gen_alloc_enter(size);
}

int gen_alloc_exit(struct pt_regs *ctx)
{
    void *addr = (void *)PT_REGS_RC(ctx);
    if (!addr)
        return 0;
    // bpf_printk("malloc_exit");
    // get size
    // u32 pid = bpf_get_current_pid_tgid() >> 32;
    // struct task_struct* curr = ;
    u32 pid = get_task_ns_pid((struct task_struct*)bpf_get_current_task());
    u64 *size = bpf_map_lookup_elem(&pid_size, &pid);
    if (!size)
        return -1;

    // record stack count
    psid apsid = {
        .pid = pid,
        .usid = u ? USER_STACK : -1,
        .ksid = k ? KERNEL_STACK: -1,
    };
    u64 *count = bpf_map_lookup_elem(&psid_count, &apsid);
    if (!count)
        bpf_map_update_elem(&psid_count, &apsid, size, BPF_NOEXIST);
    else
        (*count) += *size;

    // record pid_addr-info
    piddr a = {
        .addr = (u64)addr,
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

SEC("uretprobe/malloc")
int BPF_KRETPROBE(malloc_exit)
{
    return gen_alloc_exit(ctx);
}

SEC("uretprobe/calloc")
int BPF_KRETPROBE(calloc_exit)
{
    return gen_alloc_exit(ctx);
}

SEC("uretprobe/realloc")
int BPF_KRETPROBE(realloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uretprobe/mmap")
int BPF_KRETPROBE(mmap_exit)
{
    return gen_alloc_exit(ctx);
}

int gen_free_enter(u64 addr, size_t unsize)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // struct task_struct* curr = (struct task_struct*)bpf_get_current_task();
    // u32 pid = get_task_ns_pid(curr);
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
    if(unsize) {
        if (unsize >= *size)
            *size = 0;
        else
            (*size) -= unsize;
    }
    else
        (*size) -= info->size;
    
    if(!*size) bpf_map_delete_elem(&psid_count, &apsid);

    // del freeing addr info
    return bpf_map_delete_elem(&piddr_meminfo, &a);
}

SEC("uprobe/free")
int BPF_KPROBE(free_enter, void *addr) {
    return gen_free_enter((u64)addr, 0);
}

SEC("uprobe/realloc")
int BPF_KPROBE(realloc_enter, void *ptr, size_t size)
{
	gen_free_enter((u64)ptr, 0);
	return gen_alloc_enter(size);
}

SEC("uprobe/munmap")
int BPF_KPROBE(munmap_enter, void *addr, size_t unsize) {
    return gen_free_enter((u64)addr, unsize);
}
