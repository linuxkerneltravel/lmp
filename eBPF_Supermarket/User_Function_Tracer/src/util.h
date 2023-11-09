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
// Utility functions

#ifndef UTRACE_UTIL_H
#define UTRACE_UTIL_H

#include <stdbool.h>
#include <stddef.h>  // for size_t
#include <stdio.h>   // for perror
#include <stdlib.h>  // for exit

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define die(msg)        \
  do {                  \
    perror(msg);        \
    exit(EXIT_FAILURE); \
  } while (0)

/**
 * @brief append the string `src` to the end of `dest`
 * @details different from std::strcat, this function reallocs memory when `dest` does not have
 *          enough space
 * @return the concatenated string, which may differ from `dest` because of a possible reallocation
 */
char *restrcat(char *dest, const char *src);

/**
 * @brief resolve full path of `file` based on $PATH when it cannot be located
 * @return full path string malloced from heap
 */
char *resolve_full_path(const char *file);

/**
 * @brief get the basename of `file`
 * @details different from std::basename, this function does not modify the input `file`
 */
const char *base_name(const char *file);

/**
 * @brief check if `file` is a library
 */
bool is_library(const char *file);

/**
 * @brief exec shell command `cmd` and return its output
 * @details different from std::system, this function uses pipe to extract the output
 */
const char *system_exec(const char *cmd);

/**
 * @brief convert the `duration` in string form to unsigned long long in nanoseconds
 * @example "12us" -> 12000
 * @note there cannot be blanks before the unit
 */
unsigned long long duration_str2ns(const char *duration);

/**
 * @brief return the actual virtual address of `addr` at runtime when no-pie is set
 */
size_t resolve_addr(size_t addr);

#endif  // UTRACE_UTIL_H
