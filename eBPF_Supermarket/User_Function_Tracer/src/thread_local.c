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

#include "thread_local.h"

#include <stdlib.h>

#include "log.h"

struct thread_local* thread_local_init() {
  struct thread_local* thread_local = malloc(sizeof(struct thread_local));
  for (unsigned int i = 0; i < MAX_THREAD_NUM; i++) {
    thread_local->tids[i] = 0;
    thread_local->states[i] = STATE_UNINIT;
    thread_local->records[i] = NULL;
  }
  return thread_local;
}

unsigned int thread_local_get_index(struct thread_local* thread_local, unsigned int tid) {
  for (unsigned int i = 0; i < MAX_THREAD_NUM; i++) {
    if (!thread_local->tids[i]) {
      thread_local->tids[i] = tid;
      thread_local->records[i] = vector_init(sizeof(struct profile_record));
      return i;
    } else if (thread_local->tids[i] == tid) {
      return i;
    }
  }
  ERROR("Too many threads (>%d)\n", MAX_THREAD_NUM);
  exit(1);
}

enum FUNCSTATE thread_local_get_state(struct thread_local* thread_local, unsigned int index) {
  return thread_local->states[index];
}

void thread_local_set_state(struct thread_local* thread_local, unsigned int index,
                            enum FUNCSTATE state) {
  thread_local->states[index] = state;
}

struct profile_record* thread_local_get_record(struct thread_local* thread_local,
                                               unsigned int index, unsigned int i) {
  return (struct profile_record*)(vector_get(thread_local->records[index], i));
}

struct profile_record* thread_local_get_record_back(struct thread_local* thread_local,
                                                    unsigned int index) {
  return (struct profile_record*)(vector_back(thread_local->records[index]));
}

void thread_local_push_record(struct thread_local* thread_local, unsigned int index,
                              struct profile_record* record) {
  vector_push_back(thread_local->records[index], record);
}

void thread_local_pop_record(struct thread_local* thread_local, unsigned int index) {
  vector_pop_back(thread_local->records[index]);
}

size_t thread_local_record_size(struct thread_local* thread_local, unsigned int index) {
  return vector_size(thread_local->records[index]);
}

void thread_local_free(struct thread_local* thread_local) {
  for (unsigned int i = 0; i < MAX_THREAD_NUM; i++) {
    if (thread_local->records[i]) {
      vector_free(thread_local->records[i]);
    }
  }
  free(thread_local);
  thread_local = NULL;
}