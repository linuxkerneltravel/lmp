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

#ifndef UTRACE_PRINTER_H
#define UTRACE_PRINTER_H

#include "utrace.h"

#include <stdio.h>

#include "record.h"
#include "thread_local.h"
#include "vmem.h"

extern struct env env;

struct printer {
  FILE *out; /**< same as `env.out`, but not responsible for fclosing */
};

/**
 * @brief create and init a printer
 * @return struct printer malloced from heap
 */
struct printer *printer_init();

/**
 * @brief print `cnt` consecutive characters `c`,
 *        a helper function
 */
void print_chars(struct printer *printer, char c, int cnt);

/**
 * @brief print the time duration `ns`
 * @param[in] printer
 * @param[in] ns time duration in nanoseconds
 * @param[in] need_blank print blanks before the duration
 * @param[in] need_color print the unit with color
 * @param[in] need_sign print extra signs before the duration
 */
void print_duration(struct printer *printer, unsigned long long ns, bool need_blank,
                    bool need_color, bool need_sign);

/**
 * @brief print a header
 */
void print_header(struct printer *printer);

/**
 * @brief print a split line
 * @details just several consecutive '='
 */
void print_split_line(struct printer *printer);

/**
 * @brief print one traced entry
 * @param[in] printer
 * @param[in] vmem_table to resolve the corresponding symbol for a given address
 * @param[in] thread_local to maintain infos for each thread
 * @param[in] record to also record the traced entry when specifying `--record`
 * @param[in] user_record the traced entry to be printed
 */
void print_trace(struct printer *printer, struct vmem_table *vmem_table,
                 struct thread_local *thread_local, struct record *record,
                 const struct user_record *r);

/**
 * @brief free the `printer`
 */
void printer_free(struct printer *printer);

#endif  // UTRACE_PRINTER_H
