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
// 设置断点，为探针提供时间

#include "gdb.h"

#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

struct gdb* gdb_init(pid_t pid) {
  struct gdb* gdb = malloc(sizeof(struct gdb));
  gdb->pid = pid;
  gdb->inst = 0;
  return gdb;
}

// assert gdb != NULL
long gdb_enable_breakpoint(struct gdb* gdb, size_t addr) {
  long data = ptrace(PTRACE_PEEKDATA, gdb->pid, addr, NULL);
  gdb->inst = (uint8_t)data & 0xFF;

  uint8_t int3 = 0xCC;
  return ptrace(PTRACE_POKEDATA, gdb->pid, addr, (data & ~0xFF) | int3);
}

// assert gdb != NULL
long gdb_disable_breakpoint(struct gdb* gdb, size_t addr) {
  long data = ptrace(PTRACE_PEEKDATA, gdb->pid, addr, NULL);
  return ptrace(PTRACE_POKEDATA, gdb->pid, (data & ~0xFF) | gdb->inst);
}

// assert gdb != NULL
long gdb_continue_execution(struct gdb* gdb) { return ptrace(PTRACE_CONT, gdb->pid, NULL, NULL); }

// assert gdb != NULL
long gdb_wait_for_signal(struct gdb* gdb) {
  int wstatus;
  int options = 0;
  return waitpid(gdb->pid, &wstatus, options);
}

// assert gdb != NULL
void gdb_free(struct gdb* gdb) {
  ptrace(PTRACE_DETACH, gdb->pid, NULL, NULL);
  free(gdb);
}