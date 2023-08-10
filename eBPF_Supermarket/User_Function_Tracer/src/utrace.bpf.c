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

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, s32);
  __type(value, u64);
} function_start SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 8192 * 1024);
} records SEC(".maps");

SEC("uprobe/trace")
int BPF_KPROBE(uprobe) {
  struct profile_record *r;
  pid_t pid, tid, cpu_id;
  u64 id, ts;

  id = bpf_get_current_pid_tgid();
  tid = (u32)id;
  pid = id >> 32;
  cpu_id = bpf_get_smp_processor_id();

  r = bpf_ringbuf_reserve(&records, sizeof(*r), 0);
  if (!r) return 0;
  r->tid = tid;
  r->cpu_id = cpu_id;
  r->duration_ns = 0;
  r->ustack_sz =
      bpf_get_stack(ctx, r->ustack, sizeof(r->ustack), BPF_F_USER_STACK) / sizeof(r->ustack[0]);
  r->exit = 0;
  s32 ustack_sz = r->ustack_sz;
  ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&function_start, &ustack_sz, &ts, BPF_ANY);
  bpf_ringbuf_submit(r, 0);
  return 0;
}

SEC("uretprobe/trace")
int BPF_KRETPROBE(uretprobe) {
  struct profile_record *r;
  pid_t pid, tid, cpu_id;
  u64 id, end_ts = bpf_ktime_get_ns();
  u64 *start_ts;
  s32 ustack_sz;

  id = bpf_get_current_pid_tgid();
  cpu_id = bpf_get_smp_processor_id();
  pid = id >> 32;
  tid = (u32)id;

  r = bpf_ringbuf_reserve(&records, sizeof(*r), 0);
  if (!r) return 0;
  r->tid = tid;
  r->cpu_id = cpu_id;
  r->ustack_sz = bpf_get_stack(ctx, r->ustack, sizeof(r->ustack), BPF_F_USER_STACK) /
                 sizeof(sizeof(r->ustack[0]));
  ustack_sz = r->ustack_sz;
  start_ts = bpf_map_lookup_elem(&function_start, &ustack_sz);
  if (start_ts) r->duration_ns = end_ts - *start_ts;
  bpf_map_delete_elem(&function_start, &ustack_sz);
  r->exit = 1;
  bpf_ringbuf_submit(r, 0);
  return 0;
}