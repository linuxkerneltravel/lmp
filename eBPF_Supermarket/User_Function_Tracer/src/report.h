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
// Report the traced data in the specified format

#ifndef UTRACE_REPORT_H
#define UTRACE_REPORT_H

#include "utrace.h"

#include "printer.h"
#include "vector.h"

extern struct env env;

/**
 * @brief specify the output format
 */
enum FORMAT {
  SUMMARY,     /**< analyze the traced data */
  CHROME,      /**< JSON format, can be read by "chrome://tracing" */
  FLAME_GRAPH, /**< folded stack counts, can be processed by "brendangregg/FlameGraph" to generate
                    a flame graph */
  CALL_GRAPH,  /**< the default function call graph format */
};

struct report {
  FILE *in;                /**< point to file "./trace.data" */
  struct printer *printer; /**< used to print the traced data */
  char *trace_time;        /**< the traced time recorded in the header of "./trace.data" */
  char *cmdline;           /**< the trace command recorded in the header of "./trace.data" */
  pid_t pid; /**< the pid of the traced program recorded in the header of "./trace.data" */
  struct vector *records; /**< the trace entries (struct user_record) */
};

/**
 * @brief create and init a report
 * @return struct report malloced from heap
 */
struct report *report_init(struct printer *printer);

/**
 * @brief report the traced data in format `report->format`
 */
void do_report(struct report *report);

/**
 * @brief free the `report`
 */
void report_free(struct report *report);

#endif  // UTRACE_REPORT_H
