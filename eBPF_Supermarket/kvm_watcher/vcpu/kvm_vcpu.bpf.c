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
// author: nanshuaibo811@163.com
//
// Kernel space BPF program used for monitoring data for vCPU HLT.

#include "vmlinux.h"
#include "kvm_vcpu.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile bool execute_vcpu_wake=false;

struct vcpu_wakeup{
	u64 pad;
	__u64 ns;
	bool waited;
	bool vaild;
};

int trace_kvm_vcpu_wake(struct vcpu_wakeup *ctx){
	unsigned pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = bpf_get_current_pid_tgid();
	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	u64 hlt_time = bpf_ktime_get_ns();
	if (!e)
		return 0;
	e->waited = ctx->waited;
	e->pid = pid;
	e->tid = tid;
	e->block_ns = ctx->ns;
	e->hlt_time = hlt_time;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/kvm/kvm_vcpu_wakeup")
int tp_vcpu_wakeup(struct vcpu_wakeup *ctx)
{   
	if(execute_vcpu_wake){
		trace_kvm_vcpu_wake(ctx);
	}
	return 0;
}
