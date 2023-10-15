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
// Thread local storage, used to maintain the function stack per thread

#ifndef UTRACE_THREAD_LOCAL_H
#define UTRACE_THREAD_LOCAL_H

#include "utrace.h"

#include "vector.h"

/**
 * @brief The `index`-th entry maintains information of thread `tids[index]`
 */
struct thread_local {
  int tids[MAX_THREAD_NUM];               /**< thread ID */
  enum FUNC_STATE states[MAX_THREAD_NUM]; /**< function state: enter/exit a function */
  struct vector *records[MAX_THREAD_NUM]; /**< pending user records, entered but not exited */
};

/**
 * @brief create and init a thread_local
 * @return struct thread_local malloced from heap
 */
struct thread_local *thread_local_init();

/**
 * @brief find the index where the info of thread `tid` is stored
 */
size_t thread_local_get_index(struct thread_local *thread_local, int tid);

/**
 * @brief get the function state for the thread located at `index`
 */
enum FUNC_STATE thread_local_get_state(const struct thread_local *thread_local, size_t index);

/**
 * @brief set the function state to `state` for the thread located at `index`
 */
void thread_local_set_state(struct thread_local *thread_local, size_t index, enum FUNC_STATE state);

/**
 * @brief get the `i`-th pending user record for the thread located at `index`
 */
struct user_record *thread_local_get_record(struct thread_local *thread_local, size_t index,
                                            size_t i);

/**
 * @brief get the last pending user record for the thread located at `index`
 */
struct user_record *thread_local_get_record_back(struct thread_local *thread_local, size_t index);

/**
 * @brief add the `record` to the end of pending records for the thread located at `index`
 */
void thread_local_push_record(struct thread_local *thread_local, size_t index,
                              struct user_record *record);

/**
 * @brief pop the last pending record for the thread located at `index`
 */
void thread_local_pop_record(struct thread_local *thread_local, size_t index);

/**
 * @brief get the number of pending records for the thread located at `index`
 */
size_t thread_local_record_size(const struct thread_local *thread_local, size_t index);

/**
 * @brief free the `thread_local`
 */
void thread_local_free(struct thread_local *thread_local);

#endif  // UTRACE_THREAD_LOCAL_H
