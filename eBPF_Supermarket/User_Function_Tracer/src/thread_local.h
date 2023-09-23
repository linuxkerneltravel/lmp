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
// Thread local storage

#ifndef UTRACE_THREAD_LOCAL_H
#define UTRACE_THREAD_LOCAL_H

#include "utrace.h"

#include "vector.h"

enum FUNC_STATE { STATE_UNINIT, STATE_EXEC, STATE_EXIT };

struct thread_local {
  unsigned int tids[MAX_THREAD_NUM];
  enum FUNC_STATE states[MAX_THREAD_NUM];
  struct vector *records[MAX_THREAD_NUM];
};

struct thread_local *thread_local_init();

unsigned int thread_local_get_index(struct thread_local *thread_local, unsigned int tid);

enum FUNC_STATE thread_local_get_state(const struct thread_local *thread_local, unsigned int index);

void thread_local_set_state(struct thread_local *thread_local, unsigned int index,
                            enum FUNC_STATE state);

struct profile_record *thread_local_get_record(struct thread_local *thread_local,
                                               unsigned int index, unsigned int i);

struct profile_record *thread_local_get_record_back(struct thread_local *thread_local,
                                                    unsigned int index);

void thread_local_push_record(struct thread_local *thread_local, unsigned int index,
                              struct profile_record *record);

void thread_local_pop_record(struct thread_local *thread_local, unsigned int index);

size_t thread_local_record_size(const struct thread_local *thread_local, unsigned int index);

void thread_local_free(struct thread_local *thread_local);

#endif  // UTRACE_THREAD_LOCAL_H
