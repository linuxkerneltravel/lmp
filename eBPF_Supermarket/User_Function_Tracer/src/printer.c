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
// Print the traced data

#include "printer.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "env.h"
#include "log.h"
#include "util.h"

/**
 * @brief if the `file` supports color, print in color using ANSI escape codes
 */
static void print_color(FILE *file, const char *color) {
  char *term = getenv("TERM");
  if (isatty(fileno(file)) && !(term && !strcmp(term, "dumb"))) {
    LOG(file, "%s", color);
  }
}

struct printer *printer_init() {
  struct printer *printer = malloc(sizeof(struct printer));
  printer->out = env.out;
  return printer;
}

void print_chars(struct printer *printer, char c, int cnt) {
  while (cnt-- > 0) LOG(printer->out, "%c", c);
}

void print_duration(struct printer *printer, unsigned long long ns, bool need_blank,
                    bool need_color, bool need_sign) {
  static const char *units[] = {
    "ns", "us", "ms", " s", " m", " h",
  };
  static const char *colors[] = {
    "", "", TERM_GREEN, TERM_YELLOW, TERM_MAGENTA, TERM_RED,
  };
  static const char signs[] = {
    ' ', ' ', '+', '#', '!', '*',
  };
  static unsigned long long limits[] = {
    1000, 1000, 1000, 1000, 60, 24, 0,
  };

  unsigned long long t = ns, t_mod = ns;
  unsigned long i = 0;
  for (; i < ARRAY_SIZE(units) - 1; i++) {
    if (t < limits[i]) break;
    t_mod = t % limits[i];
    t = t / limits[i];
  }

  if (need_sign && signs[i] != ' ') print_chars(printer, signs[i], 1);
  if (need_blank) {
    LOG(printer->out, "%4llu.%03llu ", t, t_mod);
  } else {
    LOG(printer->out, "%llu.%03llu ", t, t_mod);
  }
  if (need_color) print_color(printer->out, colors[i]);
  LOG(printer->out, "%s", units[i]);
  if (need_color) print_color(printer->out, TERM_RESET);
}

void print_header(struct printer *printer) {
  if (env.show_tid) LOG(printer->out, "  TID  | ");
  if (env.show_timestamp) LOG(printer->out, "   TIMESTAMP    | ");
  LOG(printer->out, "  DURATION  |   FUNCTION CALLS\n");
}

void print_split_line(struct printer *printer) {
  int width = 30;
  if (env.show_tid) width += 9;
  if (env.show_timestamp) width += 18;
  print_chars(printer, '=', width);
  print_chars(printer, '\n', 1);
}

/**
 * @brief print one trace entry in call-graph format
 */
static void print_trace_entry_graph(struct printer *printer, enum FUNC_STATE state,
                                    const struct user_record *record) {
  const int INDENT = 2;
  if (env.show_tid) LOG(printer->out, "%6d | ", record->krecord.tid);
  if (env.show_timestamp)
    LOG(printer->out, "%llu.%06llu | ", record->krecord.timestamp / 1000000,
        record->krecord.timestamp % 1000000);
  if (record->krecord.ret) {  // exit a function
    // need_blank = true, need_color = true, need_sign = false
    print_duration(printer, record->duration_ns, true, true, false);
    LOG(printer->out, " | ");
    print_chars(printer, ' ', record->krecord.ustack_sz * INDENT);
    if (state == STATE_EXIT) {
      LOG(printer->out, "} ");
      print_color(printer->out, TERM_GRAY);
      LOG(printer->out, "/* %s", record->name);
      if (env.show_libname && record->libname) LOG(printer->out, "@%s", record->libname);
      LOG(printer->out, " */\n");
      print_color(printer->out, TERM_RESET);
    } else if (state == STATE_EXEC) {
      LOG(printer->out, "%s", record->name);
      if (env.show_libname && record->libname) LOG(printer->out, "@%s", record->libname);
      LOG(printer->out, "();\n");
    }
  } else {  // enter a function
    print_chars(printer, ' ', 11);
    LOG(printer->out, " | ");
    print_chars(printer, ' ', record->krecord.ustack_sz * INDENT);
    LOG(printer->out, "%s", record->name);
    if (env.show_libname && record->libname) LOG(printer->out, "@%s", record->libname);
    LOG(printer->out, "() {\n");
  }
}

/**
 * @brief print one trace entry in flat call-graph format
 */
static void print_trace_entry_flat(struct printer *printer, enum FUNC_STATE state,
                                   const struct user_record *record) {
  if (record->krecord.ret) {  // exit a function
    if (state == STATE_EXIT)
      LOG(printer->out, "←");
    else  // STATE_EXEC
      LOG(printer->out, "↔");
  } else {  // enter a function
    LOG(printer->out, "→");
  }
  LOG(printer->out, " [%u] ", record->krecord.ustack_sz + 1);
  if (env.show_tid) LOG(printer->out, "%u: ", record->krecord.tid);
  if (env.show_timestamp)
    LOG(printer->out, "(%llu.%06llu) ", record->krecord.timestamp / 1000000,
        record->krecord.timestamp % 1000000);
  LOG(printer->out, "%s", record->name);
  if (env.show_libname && record->libname) LOG(printer->out, "@%s", record->libname);
  if (record->krecord.ret) {
    LOG(printer->out, " [");
    // need_blank = false, need_color = false, need_sign = true
    print_duration(printer, record->duration_ns, false, false, true);
    LOG(printer->out, "]");
  }
  LOG(printer->out, "\n");
}

void print_trace(struct printer *printer, struct vmem_table *vmem_table,
                 struct thread_local *thread_local, struct record *record,
                 const struct user_record *r) {
  struct user_record curr;
  unsigned int index = thread_local_get_index(thread_local, r->krecord.tid);
  enum FUNC_STATE state = thread_local_get_state(thread_local, index);
  if (r->krecord.ret) {  // exit a function
    struct user_record *prer = thread_local_get_record_back(thread_local, index);
    curr = *r;
    if (state == STATE_EXIT) {  // also exited a function previously
      curr.duration_ns =
          curr.krecord.timestamp - prer->krecord.timestamp;  // compute the `duration_ns` now
      curr.name = prer->name;
      curr.libname = prer->libname;
      env.flat ? print_trace_entry_flat(printer, state, &curr)
               : print_trace_entry_graph(printer, state, &curr);
      if (env.do_record && !env.do_report) record_entry(record, &curr);  // also record this entry
    } else if (state == STATE_EXEC) {  // entered a function previously
      if (env.min_duration) {
        while (prer->krecord.ustack_sz > r->krecord.ustack_sz) {
          thread_local_pop_record(thread_local, index);
          prer = thread_local_get_record_back(thread_local, index);
        }
      }
      if (env.do_record && !env.do_report) record_entry(record, prer);  // record `prer`
      if (!env.show_timestamp) {  // merge entries `prer` and `curr` into one
        curr.krecord.tid = prer->krecord.tid;
        curr.krecord.ret = true;
      } else {  // otherwise, first print `prer`
        env.flat ? print_trace_entry_flat(printer, state, prer)
                 : print_trace_entry_graph(printer, state, prer);
      }
      curr.name = prer->name;
      curr.libname = prer->libname;
      curr.duration_ns =
          curr.krecord.timestamp - prer->krecord.timestamp;  // compute the `duration_ns` now
      env.flat
          ? print_trace_entry_flat(printer, env.show_timestamp ? STATE_EXIT : STATE_EXEC, &curr)
          : print_trace_entry_graph(printer, env.show_timestamp ? STATE_EXIT : STATE_EXEC, &curr);
      if (env.do_record && !env.do_report) record_entry(record, &curr);  // record `prer`
    }
    thread_local_pop_record(thread_local, index);
    thread_local_set_state(thread_local, index, STATE_EXIT);
  } else {                      // enter a function
    if (state == STATE_EXEC) {  // also entered a function previously
      if (!env.min_duration) {  // this function may be filtered by time
        // we can output the previous entry
        struct user_record *prer = thread_local_get_record_back(thread_local, index);
        env.flat ? print_trace_entry_flat(printer, state, prer)
                 : print_trace_entry_graph(printer, state, prer);
        if (env.do_record && !env.do_report) record_entry(record, prer);  // also record this entry
      }
    }

    if (vmem_table) {  // resolve the address to symbol
      const struct symbol *symbol = vmem_table_symbolize(vmem_table, r->krecord.ustack[0]);
      if (symbol) {
        curr = *r;
        curr.duration_ns = 0;
        curr.name = symbol->name;
        curr.libname = symbol->libname;
      } else {  // failed, just ignore
        return;
      }
    } else {  // the entry is from "utrace.data"
      curr = *r;
      if (!strcmp(curr.libname, "")) curr.libname = NULL;
    }
    if (env.min_duration) {
      while (thread_local_record_size(thread_local, index) > 0 &&
             thread_local_get_record_back(thread_local, index)->krecord.ustack_sz + 1 !=
                 curr.krecord.ustack_sz)
        thread_local_pop_record(thread_local, index);  // this function has be filtered by time
    }
    thread_local_push_record(thread_local, index, &curr);
    thread_local_set_state(thread_local, index, STATE_EXEC);
  }
}

void printer_free(struct printer *printer) { free(printer); }
