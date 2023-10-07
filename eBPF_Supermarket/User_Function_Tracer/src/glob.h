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
// Extended glob pattern match

#ifndef UTRACE_GLOB_H
#define UTRACE_GLOB_H

#include <stdbool.h>

/**
 * @brief extended glob match, where the `pattern` can be multiple regular glob patterns joined
 *        by ','
 * @example text = "std::forward", pattern = "main,std::*"
 */
bool glob_match_ext(const char *text, const char *pattern);

#endif  // UTRACE_GLOB_H
