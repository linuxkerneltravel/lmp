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
// author: jinyufeng2000@gmail.com
//
// eBPF用户态探针部分

#include "vmlinux.h"

#include "utrace.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static int global_sz;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, MAX_STACK_DEPTH);
} function_start SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_THREAD_NUM);
} stack_depth SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 2048 * 4096);
} records SEC(".maps");

SEC("uprobe/trace")
int BPF_KPROBE(uprobe) {
  struct profile_record *r;
  pid_t tid, cpu_id;
  __u64 ts;
  __u32 *depth_ptr;
  __u32 depth;

  tid = (__u32)bpf_get_current_pid_tgid();
  cpu_id = bpf_get_smp_processor_id();

  r = bpf_ringbuf_reserve(&records, sizeof(*r), 0);
  if (!r) return 0;

  r->tid = tid;
  r->cpu_id = cpu_id;
  r->duration_ns = 0;
  bpf_get_stack(ctx, &r->ustack, sizeof(r->ustack), BPF_F_USER_STACK);
  depth_ptr = bpf_map_lookup_elem(&stack_depth, &tid);
  if (depth_ptr)
    r->ustack_sz = depth = *depth_ptr + 1;
  else
    r->ustack_sz = depth = 0;
  r->global_sz = global_sz;
  r->timestamp = bpf_ktime_get_ns();
  ts = r->timestamp;
  r->exit = 0;
  bpf_ringbuf_submit(r, 0);

  bpf_map_update_elem(&function_start, &global_sz, &ts, BPF_NOEXIST);
  ++global_sz;
  bpf_map_update_elem(&stack_depth, &tid, &depth, BPF_ANY);
  return 0;
}

SEC("uretprobe/trace")
int BPF_KRETPROBE(uretprobe) {
  struct profile_record *r;
  __u32 current_pid;
  pid_t tid, cpu_id;
  __u64 *start_ts_ptr;
  __u64 end_ts = bpf_ktime_get_ns();
  __u32 *depth_ptr;

  tid = (__u32)bpf_get_current_pid_tgid();
  cpu_id = bpf_get_smp_processor_id();

  depth_ptr = bpf_map_lookup_elem(&stack_depth, &tid);
  if (!depth_ptr) return 0;

  r = bpf_ringbuf_reserve(&records, sizeof(*r), 0);
  if (!r) return 0;

  --global_sz;

  r->tid = tid;
  r->cpu_id = cpu_id;
  r->timestamp = end_ts;
  start_ts_ptr = bpf_map_lookup_elem(&function_start, &global_sz);
  if (start_ts_ptr) r->duration_ns = end_ts - *start_ts_ptr;
  bpf_get_stack(ctx, r->ustack, sizeof(r->ustack), BPF_F_USER_STACK);
  r->ustack_sz = *depth_ptr;
  r->global_sz = global_sz;
  r->exit = 1;

  bpf_ringbuf_submit(r, 0);

  bpf_map_delete_elem(&function_start, &global_sz);
  --*depth_ptr;
  bpf_map_update_elem(&stack_depth, &tid, depth_ptr, BPF_ANY);
  return 0;
}
