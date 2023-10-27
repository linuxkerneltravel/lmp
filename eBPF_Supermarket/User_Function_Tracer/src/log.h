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
// Tiny global logger

#ifndef UTRACE_LOG_H
#define UTRACE_LOG_H

#include <stdbool.h>
#include <stdio.h>

extern bool debug; /**< specify whether to output debug-level msg, controlled by "-d/--debug" */

/**
 * @brief output to stderr at debug level
 */
#define DEBUG(fmt, ...)                    \
  do {                                     \
    if (debug) {                           \
      fprintf(stderr, "[DEBUG] ");         \
      fprintf(stderr, fmt, ##__VA_ARGS__); \
      fprintf(stderr, "\n");               \
    }                                      \
  } while (0)

/**
 * @brief output to stderr at warn level
 */
#define WARN(fmt, ...)                   \
  do {                                   \
    fprintf(stderr, "[WARN] ");          \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    fprintf(stderr, "\n");               \
  } while (0)

/**
 * @brief output to stderr at error level
 */
#define ERROR(fmt, ...)                  \
  do {                                   \
    fprintf(stderr, "[ERROR] ");         \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    fprintf(stderr, "\n");               \
  } while (0)

/**
 * @brief output to stderr at fatal level,
 *        and exit the program with a failed status
 */
#define FATAL(fmt, ...)                  \
  do {                                   \
    fprintf(stderr, "[FATAL] ");         \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    fprintf(stderr, "\n");               \
    exit(EXIT_FAILURE);                  \
  } while (0)

/**
 * @brief output to the given `file` without appending a '\n'
 */
#define LOG(file, fmt, ...)            \
  do {                                 \
    fprintf(file, fmt, ##__VA_ARGS__); \
  } while (0)

#define TERM_RED "\033[0;31m"
#define TERM_GREEN "\033[0;32m"
#define TERM_YELLOW "\033[0;33m"
#define TERM_MAGENTA "\033[0;35m"
#define TERM_GRAY "\033[0;90m"
#define TERM_RESET "\033[0m"

#endif  // UTRACE_LOG_H
