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
#ifndef __KVM_VCPU_H
#define __KVM_VCPU_H

#include "kvm_watcher.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct vcpu_wakeup{
	u64 pad;
	__u64 ns;
	bool waited;
	bool vaild;
};

static int trace_kvm_vcpu_wakeup(struct vcpu_wakeup *ctx,void *rb,pid_t vm_pid)
{
	unsigned pid = bpf_get_current_pid_tgid() >> 32;
	if (vm_pid == 0 || pid == vm_pid){
		u32 tid = bpf_get_current_pid_tgid();
		struct vcpu_wakeup_event *e;
		e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
		if (!e){
			return 0;
		}
		u64 hlt_time = bpf_ktime_get_ns();
		e->waited = ctx->waited;
		e->process.pid = pid;
		e->process.tid = tid;
		e->dur_hlt_ns = ctx->ns;
		e->hlt_time = hlt_time;
		bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}
#endif /* __KVM_VCPU_H */
