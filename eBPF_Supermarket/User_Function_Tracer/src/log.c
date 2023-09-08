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

void log_color(FILE* file, const char* color) {
  char* term = getenv("TERM");
  if (isatty(fileno(file)) && !(term && !strcmp(term, "dumb"))) {
    LOG(file, "%s", color);
  }
}

void log_char(FILE* file, char c, int cnt) {
  while (cnt > 0) {
    LOG(file, "%c", c);
    --cnt;
  }
}

void log_header(FILE* file, int cpu, int tid, int timestamp) {
  if (cpu) {
    LOG(file, " CPU");
    log_split(file);
  }
  if (tid) {
    LOG(file, "  TID ");
    log_split(file);
  }
  if (timestamp) {
    LOG(file, "   TIMESTAMP  ");
    log_split(file);
  }
  LOG(file, "  DURATION ");
  log_split(file);
  LOG(file, "  FUNCTION CALLS\n");
}

void log_footer(FILE* file, int cpu, int tid, int timestamp) {
  int cnt = 30;
  if (cpu) {
    cnt += 6;
  }
  if (tid) {
    cnt += 8;
  }
  if (timestamp) {
    cnt += 16;
  }
  log_char(file, '=', cnt);
  log_char(file, '\n', 1);
}

void log_split(FILE* file) { LOG(file, " | "); }

void log_cpuid(FILE* file, int cpuid) { LOG(file, "%4d", cpuid); }

void log_tid(FILE* file, int tid) { LOG(file, "%6d", tid); }

void log_timestamp(FILE* file, unsigned long long timestamp) { LOG(file, "%llu", timestamp); }

void log_trace_data(FILE* file, unsigned int* cpuid, unsigned int* tid,
                    unsigned long long* timestamp, unsigned long long duration,
                    unsigned int stack_sz, const char* function_name, int exit,
                    enum FUNCSTATE state, int flat) {
  const int INDENT = 2;
  if (flat) {
    if (exit) {
      if (state == STATE_EXIT) {
        LOG(file, "← [%u] ", stack_sz);
      } else if (state == STATE_EXEC) {
        LOG(file, "↔ [%u] ", stack_sz);
      }
      if (cpuid && tid) {
        LOG(file, "%u/%u: ", *tid, *cpuid);
      } else if (cpuid) {
        LOG(file, "%u: ", *cpuid);
      } else if (tid) {
        LOG(file, "%u: ", *tid);
      }
      if (timestamp) {
        LOG(file, "(%llu) ", *timestamp);
      }
      LOG(file, "%s [+", function_name);
      log_duration(file, duration, 0);
      LOG(file, "]\n");
    } else {
      LOG(file, "→ [%u] ", stack_sz);
      if (cpuid && tid) {
        LOG(file, "%u/%u: ", *tid, *cpuid);
      } else if (cpuid) {
        LOG(file, "%u: ", *cpuid);
      } else if (tid) {
        LOG(file, "%u: ", *tid);
      }
      if (timestamp) {
        LOG(file, "(%llu) ", *timestamp);
      }
      LOG(file, "%s\n", function_name);
    }
  } else {
    if (cpuid) {
      log_cpuid(file, *cpuid);
      log_split(file);
    }
    if (tid) {
      log_tid(file, *tid);
      log_split(file);
    }
    if (timestamp) {
      log_timestamp(file, *timestamp);
      log_split(file);
    }
    if (exit) {
      log_duration(file, duration, 1);
      log_split(file);
      log_char(file, ' ', stack_sz * INDENT);
      if (state == STATE_EXIT) {
        LOG(file, "} ");
        log_color(file, TERM_GRAY);
        LOG(file, "/* %s */\n", function_name);
        log_color(file, TERM_NC);
      } else if (state == STATE_EXEC) {
        LOG(file, "%s();\n", function_name);
      }
    } else {
      log_char(file, ' ', 11);
      log_split(file);
      log_char(file, ' ', stack_sz * INDENT);
      LOG(file, "%s() {\n", function_name);
    }
  }
}

void log_duration(FILE* file, unsigned long long ns, int blank) {
  static char* units[] = {
      "ns", "us", "ms", " s", " m", " h",
  };
  static unsigned long long limit[] = {
      1000, 1000, 1000, 1000, 60, 24, 0,
  };

  unsigned long long t = ns, t_mod = 0;
  int i = 0;
  while (i < sizeof(units) / sizeof(units[0]) - 1) {
    if (t < limit[i]) break;
    t_mod = t % limit[i];
    t = t / limit[i];
    ++i;
  }

  if (blank) {
    LOG(file, "%4llu.%03llu %s", t, t_mod, units[i]);
  } else {
    LOG(file, "%llu.%03llu %s", t, t_mod, units[i]);
  }
}