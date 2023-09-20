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

#include "demangle.h"

#include <string.h>

char *demangle(const char *mangled_name) {
  char *demangled_name;
  int status;

  // ensure mangled_name is really mangled (start with "_Z")
  if (strncmp(mangled_name, "_Z", 2) == 0) {
    demangled_name = __cxa_demangle(mangled_name, NULL, NULL, &status);
    if (status == 0) {
      size_t len = strlen(demangled_name);
      if (demangled_name[len - 1] == ')') {  // convert "f()" to just "f"
        while (1) {
          --len;
          char c = demangled_name[len];
          demangled_name[len] = '\0';
          if (c == '(') break;
        }
      }
      return demangled_name;
    }
  }

  return strdup(mangled_name);
}