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

#define MAX_THREAD_NUM 32
#define MAX_STACK_DEPTH 128
#define MAX_SYMBOL_LEN 1024
#define MAX_PATH_LEN 256

typedef unsigned long stack_trace_t[MAX_STACK_DEPTH];

/**
 * @brief 内核态传给用户态的数据
 */
struct profile_record {
  unsigned int tid;      /**< 线程编号 */
  unsigned int next_tid; /**< 切换后的线程编号 */
  unsigned int cpu_id;   /**< CPU编号 */

  unsigned long long timestamp;   /**< 时间戳 */
  unsigned long long duration_ns; /**< 函数时延 */

  unsigned int ustack_sz; /**< 用户栈大小 */
  stack_trace_t ustack;   /**< 用户栈 */

  unsigned int global_sz; /**< 当前函数深度（考虑了多线程） */

  int exit; /**< 是否为函数退出时 */
};

#endif  // UTRACE_UTRACE_H