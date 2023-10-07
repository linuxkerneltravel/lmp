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
// Set breakpoints in the traced program, to record its memory regions and attach uprobes

#ifndef UTRACE_GDB_H
#define UTRACE_GDB_H

#include <stdint.h>     // for uint8_t
#include <sys/types.h>  // for pid_t

struct gdb {
  pid_t pid;          /**< process ID of the traced program */
  uint8_t saved_inst; /**< store the inst overwritten by int3 when setting breakpoints */
};

/**
 * @brief create and init a gdb
 * @param[in] pid process ID of the traced program
 * @return struct gdb malloced from heap
 */
struct gdb *gdb_init(pid_t pid);

/**
 * @brief enable a breakpoint at `addr`
 */
long gdb_enable_breakpoint(struct gdb *gdb, size_t addr);

/**
 * @brief disable a previously set breakpoint at `addr`
 */
long gdb_disable_breakpoint(const struct gdb *gdb, size_t addr);

/**
 * @brief let the traced program continue to exec
 */
long gdb_continue_execution(const struct gdb *gdb);

/**
 * @brief blocked wait until the traced program is stopped by a signal
 */
long gdb_wait_for_signal(const struct gdb *gdb);

/**
 * @brief detach from the traced program
 */
long gdb_detach(const struct gdb *gdb);

/**
 * @brief free the `gdb`
 */
void gdb_free(struct gdb *gdb);

#endif  // UTRACE_GDB_H
