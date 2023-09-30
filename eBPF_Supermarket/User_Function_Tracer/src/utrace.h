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
// Data recorded in kernel-side and passed to user-side

#ifndef UTRACE_UTRACE_H
#define UTRACE_UTRACE_H

#include <stdbool.h>

#define MAX_STACK_SIZE 32
#define MAX_THREAD_NUM 64
#define MAGIC_COMB 10

/**
 * @brief Represent the data recorded in kernel-side and passed to user-side
 */
struct profile_record {
  unsigned int tid;      /**< thread ID */
  unsigned int next_tid; /**< switched thread ID */
  unsigned int cpu_id;   /**< CPU ID */

  unsigned long long duration_ns; /**< duration (ns) */

  unsigned int ustack_sz;                    /**< user stack size */
  unsigned long long ustack[MAX_STACK_SIZE]; /**< user stack */

  unsigned long long timestamp; /**< timestamp */

  bool ret; /**< is function ret */

  const char *name; /**< function name, resolve in user-side */
  const char *libname;
};

#endif  // UTRACE_UTRACE_H
