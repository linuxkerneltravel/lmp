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

#include <stdlib.h>
#include <string.h>

#include "demangle.h"

char *demangle(const char *mangled_name) {
  char *original_name;
  long len = MAX_MANGLED_LEN;
  long name_len;
  int status;

  if (strncmp(mangled_name, "_Z", 2) == 0) {
    __cxa_demangle(mangled_name, NULL, &len, &status);
    if (status < 0) return strdup(mangled_name);

    original_name = malloc(len);
    __cxa_demangle(mangled_name, original_name, &len, &status);

    name_len = strlen(original_name);
    if (original_name[name_len - 1] == ')') {
      int cont = 1;
      while (cont) {
        --name_len;
        if (original_name[name_len] == '(') cont = 0;
        original_name[name_len] = 0;
      }
    }
    return original_name;
  }

  return strdup(mangled_name);
}