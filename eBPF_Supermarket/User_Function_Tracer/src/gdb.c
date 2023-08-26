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

struct gdb* new_gdb(pid_t pid) {
  struct gdb* gdb = (struct gdb*)malloc(sizeof(struct gdb));
  gdb->pid = pid;
  return gdb;
}

void enable_breakpoint(struct gdb* gdb, uint64_t addr) {
  long data = ptrace(PTRACE_PEEKDATA, gdb->pid, addr, NULL);
  gdb->inst = (uint8_t)data & 0xFF;

  uint64_t int3 = 0xCC;
  ptrace(PTRACE_POKEDATA, gdb->pid, addr, (data & ~0xFF) | int3);
}

void disable_breakpoint(struct gdb* gdb, uint64_t addr) {
  long data = ptrace(PTRACE_PEEKDATA, gdb->pid, addr, NULL);
  ptrace(PTRACE_POKEDATA, gdb->pid, (data & ~0xFF) | gdb->inst);
}

long continue_execution(struct gdb* gdb) { return ptrace(PTRACE_CONT, gdb->pid, NULL, NULL); }

long wait_for_signal(struct gdb* gdb) {
  int wstatus;
  int options = 0;
  return waitpid(gdb->pid, &wstatus, options);
}

void delete_gdb(struct gdb* gdb) {
  ptrace(PTRACE_DETACH, gdb->pid, NULL, NULL);
  free(gdb);
}