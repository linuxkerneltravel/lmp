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
// Save command line arguments info

#ifndef UTRACE_ENV_H
#define UTRACE_ENV_H

#include <stdio.h>  // for FILE*

#include "report.h"
#include "vector.h"

struct env {
  char *argv[32];                    /**< -c/-commond */
  bool avg_self;                     /**< --avg-self */
  bool avg_total;                    /**< --avg-total */
  bool flat;                         /**< --flat */
  enum FORMAT format;                /**< --format */
  char *func_pattern;                /**< -f/--function */
  char *lib_pattern;                 /**< -l/--lib */
  bool show_libname;                 /**< --libname */
  unsigned int max_depth;            /**< --max-depth */
  char *nest_lib_pattern;            /**< --nest-lib */
  char *no_func_pattern;             /**< --no-function */
  char *no_lib_pattern;              /**< --no-lib */
  bool no_aslr;                      /**< --no-randomize-addr */
  FILE *out;                         /**< -o/--output */
  bool percent_self;                 /**< --percent-self */
  bool percent_total;                /**< --percent-total */
  pid_t pid;                         /**< -p/--pid */
  bool do_record;                    /**< --record */
  bool do_report;                    /**< --report */
  unsigned long long sample_time_ns; /**< --sample-time */
  bool show_tid;                     /**< --tid */
  struct vector *tids;               /**< --tid-filter */
  bool show_timestamp;               /**< --timestamp */
  unsigned long long min_duration;   /**< --time-filter */
  char *user;                        /**< -u/--user */
};

#endif  // UTRACE_ENV_H
