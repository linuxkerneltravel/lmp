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
// Record the traced data

#ifndef UTRACE_RECORD_H
#define UTRACE_RECORD_H

#include "utrace.h"

#include <stdio.h>
#include <sys/types.h>

struct record {
  FILE *out; /**< point to file "./trace.data" */
  pid_t pid; /**< process ID of the traced program */
};

/**
 * @brief create and init a record
 * @return struct record malloced from heap
 */
struct record *record_init(pid_t pid);

/**
 * @brief record some basic info
 * @param[in] argc main()'s argc
 * @param[in] argv main()'s argv
 * @details record 1. the traced time
 *                 2. the trace command
 *                 3. the pid of the traced program
 */
void record_header(struct record *record, int argc, char **argv);

/**
 * @brief record one traced entry
 */
void record_entry(struct record *record, struct user_record *user_record);

/**
 * @brief free the `record`
 */
void record_free(struct record *record);

#endif  // UTRACE_RECORD_H
