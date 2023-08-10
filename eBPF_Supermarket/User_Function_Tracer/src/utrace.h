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
// 记录从内核态传给用户态的数据

#ifndef UTRACE_UTRACE_H
#define UTRACE_UTRACE_H

#define MAX_SYMBOL_LEN 64
#define MAX_STACK_DEPTH 128
#define MAX_PATH_LEN 256

typedef unsigned long long stack_trace_t[MAX_STACK_DEPTH];

/**
 * @brief 内核态传给用户态的数据
 */
struct profile_record {
  unsigned int tid;    /**< 线程编号 */
  unsigned int cpu_id; /**< CPU编号 */

  unsigned long long duration_ns; /**< 函数时延 */

  unsigned int kstack_sz; /**< 内核栈大小 */
  stack_trace_t kstack;   /**< 内核栈 */

  unsigned int ustack_sz; /**< 用户栈大小 */
  stack_trace_t ustack;   /**< 用户栈 */

  int exit; /**< 是否为函数退出时 */
};

#endif  // UTRACE_UTRACE_H