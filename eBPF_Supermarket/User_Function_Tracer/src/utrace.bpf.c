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
// The attached eBPF program run by Linux kernel

#include "vmlinux.h"

#include "utrace.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/**
 * @brief maintain function stack for each thread
 * @param[in] key thread ID
 * @param[out] value current stack size
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, __u32);
  __uint(max_entries, MAX_THREAD_NUM);
} stack_size SEC(".maps");

#define TID_SHIFT 10
/**
 * @brief record the timestamp when the last function started for each thread
 * @param[in] key global ID, computed by ``(tid << TID_SHIFT | stack_sz)`,
 *            which uniquely corresponds to a pair `(tid, stack_sz)`
 * @param[out] value the start timestamp
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, (MAX_THREAD_NUM) * (MAX_STACK_SIZE));
} function_start SEC(".maps");

/**
 * @brief send the traced data `kernel_record` to the user-side
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 2048 * 4096);
} records SEC(".maps");

const volatile unsigned int max_depth = 0;          /**< set by --max-depth */
const volatile unsigned long long min_duration = 0; /**< set by --time-filter */

// triggered every time a function is entered
SEC("uprobe/trace")
int uprobe(struct pt_regs *ctx) {
  struct kernel_record *r;
  int tid;
  __u64 ts;
  __u32 *local_size_pt;
  __u32 local_size, global_id;

  tid = (int)bpf_get_current_pid_tgid();  // thread ID is the lower 32 bits

  local_size_pt = bpf_map_lookup_elem(&stack_size, &tid);  // get previouse local stack size
  // apply depth filter (current stack size is local_size + 1, and local_size is 0 indexed, but
  // max_depth is 1 indexed)
  if (local_size_pt && *local_size_pt + 2 > max_depth) {
    local_size = *local_size_pt + 1;
    bpf_map_update_elem(&stack_size, &tid, &local_size, BPF_ANY);
    return 0;
  }

  r = bpf_ringbuf_reserve(&records, sizeof(*r), 0);
  if (!r) return 0;

  r->tid = tid;
  bpf_get_stack(ctx, &r->ustack, sizeof(r->ustack), BPF_F_USER_STACK);
  if (local_size_pt) {
    r->ustack_sz = local_size = *local_size_pt + 1;
  } else {
    r->ustack_sz = local_size = 0;
  }

  bpf_map_update_elem(&stack_size, &tid, &local_size, BPF_ANY);
  global_id = (tid << TID_SHIFT) | local_size;  // compute the global ID

  r->timestamp = ts = bpf_ktime_get_ns();  // record timestamp as late as possible
  r->ret = false;
  bpf_ringbuf_submit(r, 0);

  bpf_map_update_elem(&function_start, &global_id, &ts, BPF_ANY);

  return 0;
}

// triggered every time a function is going to exit
SEC("uretprobe/trace")
int uretprobe(struct pt_regs *ctx) {
  struct kernel_record *r;
  int tid;
  __u64 *start_ts_pt;
  __u32 *local_size_pt;
  __u32 global_id;
  __u64 end_ts = bpf_ktime_get_ns(), duration_ns;  // record timestamp as early as possible

  tid = (int)bpf_get_current_pid_tgid();

  local_size_pt = bpf_map_lookup_elem(&stack_size, &tid);
  if (!local_size_pt) {  // this function has be filtered, just ignore
    return 0;
  } else if (*local_size_pt + 1 > max_depth) {  // apply depth filter (local_size is 0 indexed, but
                                                // max_depth is 1 indexed)
    --*local_size_pt;
    bpf_map_update_elem(&stack_size, &tid, local_size_pt, BPF_ANY);
    return 0;
  }

  global_id = (tid << TID_SHIFT) | *local_size_pt;
  start_ts_pt = bpf_map_lookup_elem(&function_start, &global_id);
  if (start_ts_pt) {
    duration_ns = end_ts - *start_ts_pt;
  } else {
    return 0;
  }

  if (duration_ns < min_duration) {  // apply time filter
    --*local_size_pt;
    bpf_map_update_elem(&stack_size, &tid, local_size_pt, BPF_ANY);
    return 0;
  }

  r = bpf_ringbuf_reserve(&records, sizeof(*r), 0);
  if (!r) return 0;

  r->tid = tid;
  bpf_get_stack(ctx, r->ustack, sizeof(r->ustack), BPF_F_USER_STACK);
  r->ustack_sz = *local_size_pt;

  r->timestamp = end_ts;
  r->ret = true;
  bpf_ringbuf_submit(r, 0);

  --*local_size_pt;
  bpf_map_update_elem(&stack_size, &tid, local_size_pt, BPF_ANY);

  return 0;
}
