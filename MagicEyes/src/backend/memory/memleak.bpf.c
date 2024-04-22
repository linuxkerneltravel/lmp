// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct whole_info {
	u64 whole_size;
    u64 whole_number;
	};

struct single_info {
	u64 single_size;
	u64 times;
	u32 stack_id;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 256 * 1024);
        __type(key, u64);
        __type(value, struct single_info);
} addr_to_single_info SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 256 * 1024);
        __type(key, u32);
        __type(value, struct whole_info);
} stack_id_to_whole_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 256 * 1024);
	__uint(key_size, sizeof(u32));
	__uint(value_size, 127 * sizeof(u64));
}stack_id_to_stack_trace_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(pid_t));
    __uint(value_size, sizeof(u64));
}pid_to_malloc_size SEC(".maps");

/** 内核的内存分配？ */
SEC("tracepoint/kmem/kmalloc")
int tracepoint__kmem__kmalloc(struct trace_event_raw_kmem_alloc* ctx)	
{
	u64 ip[20];
	u64 i, stack_trace_ips_whole_size, stack_trace_ips_number, malloc_size, malloc_addr;
	pid_t pid;
	struct whole_info *pre_wi, wi={0};
	struct single_info si={0};

	malloc_size = (u64)ctx->bytes_alloc;
	if(malloc_size == 0)
		return 0;

	malloc_addr = (u64)ctx->ptr;
	if(malloc_addr == 0) 
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;

	si.single_size = malloc_size;
	si.times = bpf_ktime_get_ns();
	si.stack_id = bpf_get_stackid(ctx, &stack_id_to_stack_trace_ips, BPF_F_USER_STACK);

	bpf_map_update_elem(&addr_to_single_info, &malloc_addr, &si, BPF_ANY);
	pre_wi = bpf_map_lookup_elem(&stack_id_to_whole_info, &(si.stack_id));

	if(pre_wi != 0)
		wi = *pre_wi;

	wi.whole_size += si.single_size;
	wi.whole_number += 1;
	bpf_map_update_elem(&stack_id_to_whole_info, &(si.stack_id), &wi, BPF_ANY);
	
	bpf_printk("========================kmalloc==========================");
	bpf_printk("pid = %d, malloc_size = %llu, malloc_addr = %p\n", pid, malloc_size, malloc_addr);

	stack_trace_ips_whole_size = bpf_get_stack(ctx, ip, sizeof(ip), 0);
	if(stack_trace_ips_whole_size < 0){
		bpf_printk("call bpf_get_stack faill\n");
		return 0;
	}

	stack_trace_ips_number = stack_trace_ips_whole_size / sizeof(ip[0]);
	for(i = 0; i < (stack_trace_ips_number < 19 ? stack_trace_ips_number : 19); i++) 
		bpf_printk("stack_id = %llu, ip[%llu] = %p\n", si.stack_id, i, ip[i]);
	
	return 0;
}

SEC("tracepoint/kmem/kfree")
int tracepoint__kmem__kfree(struct trace_event_raw_kfree* ctx)
{
	u64 ip[20];
	u64 i, stack_trace_ips_whole_size, stack_trace_ips_number, free_addr;
	u32 stack_id;
	pid_t pid;
	struct whole_info *pre_wi, wi={0};
	struct single_info *pre_si, si = {0};

	free_addr =(u64)ctx->ptr;
	if(free_addr == 0)
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;

	pre_si = bpf_map_lookup_elem(&addr_to_single_info, &free_addr);
	if(pre_si == NULL)
		return 0;

	si = *pre_si;
	bpf_map_delete_elem(&addr_to_single_info, &free_addr);

	pre_wi = bpf_map_lookup_elem(&stack_id_to_whole_info, &(si.stack_id));
	if(pre_wi != 0)
		wi = *pre_wi;

	if(si.single_size > wi.whole_size)
		wi.whole_size = 0;
	else
		wi.whole_size -=si.single_size;

	if(wi.whole_number > 0)
		wi.whole_number -= 1;

	bpf_map_update_elem(&stack_id_to_whole_info, &(si.stack_id), &wi, BPF_ANY);

	bpf_printk("========================kfree==========================");
	bpf_printk("pid = %d, free_size = %llu, free_addr = %p", pid, si.single_size, free_addr);

	stack_id = bpf_get_stackid(ctx, &stack_id_to_stack_trace_ips, BPF_F_USER_STACK);
	stack_trace_ips_whole_size = bpf_get_stack(ctx, ip, sizeof(ip), 0);
	if(stack_trace_ips_whole_size < 0){
		bpf_printk("call bpf_get_stack faill\n");
		return 0;
	}

	stack_trace_ips_number = stack_trace_ips_whole_size / sizeof(ip[0]);
	for(i = 0; i < (stack_trace_ips_number < 19 ? stack_trace_ips_number : 19); i++) 
		bpf_printk("stack_id = %u, ip[%llu] = %p\n", stack_id, i, ip[i]);

	return 0;
}

SEC("kprobe/vmalloc")
int kprobe__vmalloc(struct pt_regs *ctx)
{
	pid_t pid;
    u64 malloc_size = (u64)PT_REGS_PARM1(ctx);
	if (malloc_size == 0)
    	return 0;
	
	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&pid_to_malloc_size, &pid, &malloc_size, BPF_ANY);

    return 0;
}

SEC("kretprobe/vmalloc")
int kretprobe_vmalloc(struct pt_regs *ctx)
{
	u64 ip[20];
    u64 i, stack_trace_ips_whole_size, stack_trace_ips_number, malloc_size, malloc_addr, *malloc_size_ptr;
	pid_t pid;
	struct whole_info *pre_wi, wi={0};
	struct single_info si={0};

	pid = bpf_get_current_pid_tgid() >> 32;
	malloc_size_ptr =(u64*) bpf_map_lookup_elem(&pid_to_malloc_size, &pid);
	if (malloc_size_ptr == NULL)
    	return 0;

	malloc_size = *malloc_size_ptr;
	bpf_map_delete_elem(&pid_to_malloc_size, &pid);
	
	malloc_addr = (u64)PT_REGS_RC(ctx);
	if (!malloc_addr)
		return 0; 

	si.single_size = malloc_size;
	si.times = bpf_ktime_get_ns();
	si.stack_id = bpf_get_stackid(ctx, &stack_id_to_stack_trace_ips,  BPF_F_USER_STACK);

	bpf_map_update_elem(&addr_to_single_info, &malloc_addr, &si, BPF_ANY);

	pre_wi = bpf_map_lookup_elem(&stack_id_to_whole_info, &(si.stack_id));
	if(pre_wi != 0)
		wi = *pre_wi;

	wi.whole_size += si.single_size;
	wi.whole_number += 1;
	bpf_map_update_elem(&stack_id_to_whole_info, &(si.stack_id), &wi, BPF_ANY);

	bpf_printk("========================vmalloc==========================");
	bpf_printk("pid = %d, malloc_size = %llu, malloc_addr = %p\n", pid, malloc_size, malloc_addr);

	stack_trace_ips_whole_size = bpf_get_stack(ctx, ip, sizeof(ip), 0);
	if(stack_trace_ips_whole_size < 0){
		bpf_printk("call bpf_get_stack faill\n");
		return 0;
	}

	stack_trace_ips_number = stack_trace_ips_whole_size / sizeof(ip[0]);
	for(i = 0; i < (stack_trace_ips_number < 19 ? stack_trace_ips_number : 19); i++)
		bpf_printk("stack_id = %u, ip[%llu] = %p\n", si.stack_id, i, ip[i]);

	return 0;
}

SEC("kprobe/vfree")
int kprobe__vfree(struct pt_regs *ctx)
{
    u64 ip[20];
    u64 i, stack_trace_ips_whole_size, stack_trace_ips_number;
	u32 stack_id;
    pid_t pid;
	struct whole_info *pre_wi, wi={0};
	struct single_info *pre_si, si = {0};
    void *free_addr = (void *)PT_REGS_PARM1(ctx);

	if(free_addr == 0)
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;

	pre_si = bpf_map_lookup_elem(&addr_to_single_info, &free_addr);
	if(pre_si == 0)
		return 0;

	si = *pre_si;
	bpf_map_delete_elem(&addr_to_single_info, &free_addr);

	pre_wi = bpf_map_lookup_elem(&stack_id_to_whole_info, &(si.stack_id));
	if(pre_wi != 0)
		wi = *pre_wi;

	if(si.single_size > wi.whole_size)
		wi.whole_size = 0;
	else
		wi.whole_size -=si.single_size;

	if(wi.whole_number > 0)
		wi.whole_number -= 1;

	bpf_map_update_elem(&stack_id_to_whole_info, &(si.stack_id), &wi, BPF_ANY);


	bpf_printk("========================vfree==========================");
	bpf_printk("pid = %d, free_size = %llu, free_addr = %p", pid, si.single_size, free_addr);

	stack_trace_ips_whole_size = bpf_get_stack(ctx, ip, sizeof(ip), 0);
	if(stack_trace_ips_whole_size < 0){
		bpf_printk("call bpf_get_stack faill\n");
		return 0;
	}

	stack_id = bpf_get_stackid(ctx, &stack_id_to_stack_trace_ips, BPF_F_USER_STACK);
	stack_trace_ips_number = stack_trace_ips_whole_size / sizeof(ip[0]);
	for(i = 0; i < (stack_trace_ips_number < 19 ? stack_trace_ips_number : 19); i++)
		bpf_printk("stack_id = %u, ip[%llu] = %p\n", stack_id, i, ip[i]);

	return 0;
}
