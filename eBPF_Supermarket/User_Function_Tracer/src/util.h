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
#include <stddef.h> // for size_t

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define die(msg)        \
  do {                  \
    perror(msg);        \
    exit(EXIT_FAILURE); \
  } while (0)

char *restrcat(char *str1, const char *str2);

char *resolve_full_path(const char *file);

const char *base_name(const char *file);

bool is_library(const char *file);

unsigned long long duration_str2ns(const char *duration);

size_t resolve_addr(size_t addr);

#endif  // UTRACE_UTIL_H
