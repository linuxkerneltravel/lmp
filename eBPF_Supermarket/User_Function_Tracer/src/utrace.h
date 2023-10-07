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
// The traced data to be maintained every time entering or exiting a function

#ifndef UTRACE_UTRACE_H
#define UTRACE_UTRACE_H

#include <stdbool.h>

#define MAX_STACK_SIZE 32
#define MAX_THREAD_NUM 32

/**
 * @brief represent the traced data recorded in kernel-side and passed to user-side
 */
struct kernel_record {
  int tid;                      /**< thread ID */
  unsigned int ustack_sz;       /**< user stack size */
  unsigned long long ustack[1]; /**< user stack; we only need to record the current address */
  unsigned long long timestamp; /**< timestamp */
  bool ret;                     /**< is function ret */
};

/**
 * @brief represent the traced data supplemented and used on the user side
 */
struct user_record {
  struct kernel_record krecord;   /**< kernel-side data */
  unsigned long long duration_ns; /**< function duration */
  char *name;                     /**< function name; malloced from heap when reporting */
  char *libname;                  /**< library name; malloced from heap when reporting */
};

/**
 * @brief represent the current function state
 *        STATE_UNINIT: not started yet
 *        STATE_EXEC:   just executed a function
 *        STATE_EXIT:   just exited a function
 */
enum FUNC_STATE { STATE_UNINIT, STATE_EXEC, STATE_EXIT };

#endif  // UTRACE_UTRACE_H
