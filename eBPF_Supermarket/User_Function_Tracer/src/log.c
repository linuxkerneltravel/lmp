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
// 提供日志打印

#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int debug;

void log_color(const char* color) {
  char* term = getenv("TERM");
  if (isatty(fileno(stdout)) && !(term && !strcmp(term, "dumb"))) {
    LOG("%s", color);
  }
}

void log_char(char c, int cnt) {
  while (cnt > 0) {
    LOG("%c", c);
    --cnt;
  }
}

void log_header() { LOG(" CPU |   TID  |   DURATION  |   FUNCTION CALLS\n"); }

void log_tid(int tid) { LOG("%6d", tid); }

void log_cpuid(int cpuid) { LOG("%4d", cpuid); }

void log_split() { LOG(" | "); }

void log_time(size_t ns) {
  static char* units[] = {
      "ns", "us", "ms", " s", " m", " h",
  };
  static size_t limit[] = {
      1000, 1000, 1000, 1000, 60, 24, 0,
  };

  size_t t = ns, t_mod = 0;
  int i = 0;
  while (i < sizeof(units) / sizeof(units[0]) - 1) {
    if (t < limit[i]) break;
    t_mod = t % limit[i];
    t = t / limit[i];
    ++i;
  }

  LOG("%4zu.%03zu %s", t, t_mod, units[i]);
}