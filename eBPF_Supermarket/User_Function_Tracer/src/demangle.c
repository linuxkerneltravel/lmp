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
// 还原C++重整后的符号

#include "utrace.h"

#include "demangle.h"

#include <stdlib.h>
#include <string.h>

char *demangle(const char *mangled_name) {
  char *original_name;
  long len = MAX_SYMBOL_LEN;
  int status;

  /** 确保只还原重整过的符号（以"_Z"起始）*/
  if (mangled_name[0] != '_' || mangled_name[1] != 'Z') return strdup(mangled_name);

  __cxa_demangle(mangled_name, NULL, &len, &status);
  if (status < 0) return strdup(mangled_name);

  original_name = malloc(len);
  __cxa_demangle(mangled_name, original_name, &len, &status);

  return original_name;
}
