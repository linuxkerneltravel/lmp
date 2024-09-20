// Copyright 2024 The EBPF performance testing Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: yys2020haha@163.com
//
// Kernel space BPF program used for eBPF performance testing.
#include "analyze_map.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct {
    __uint(type,BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,1024);
} rb SEC(".maps");

static struct common_event *e;
// 对比Map类型中的hash和array的性能
SEC("tracepoint/raw_syscalls/sys_enter")
int tp_sys_entry(struct trace_event_raw_sys_enter *args) {
	return analyze_maps(args,&rb,e);
}
