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

#include <stdlib.h>
#include <string.h>

static char *simplify(char *name) {
  size_t len = strlen(name);
  size_t updated_len = 0;

  for (size_t i = 0; i < len; i++) {  // remove chars inside "<>"
    if (name[i] == '<') {
      size_t j = i + 1;
      int nested = 1;
      while (j < len && nested > 0) {
        if (name[j] == '<') {
          ++nested;
        } else if (name[j] == '>') {
          --nested;
        }
        ++j;
      }
      i = j - 1;
    } else {
      name[updated_len] = name[i];
      ++updated_len;
    }
  }
  name[updated_len] = '\0';
  len = updated_len;

  if (len) {
    for (size_t i = len - 1; i > 0; i--) {  // remove the last "(...)"
      if (name[i] == ')') {
        size_t j = i + 1;
        int nested = 1;
        while (i > 0) {
          --i;
          if (name[i] == ')') {
            ++nested;
          } else if (name[i] == '(') {
            --nested;
            if (!nested) break;
          }
        }
        while (j < len) {
          name[i] = name[j];
          ++i;
          ++j;
        }
        name[i] = '\0';
        len = i;
        break;
      }
    }
  }

  for (size_t i = 0; i < len; i++) {
    if (name[i] == '{') {
      size_t prei = i;
      size_t j = i + 1;
      int nested = 0;
      while (j < len) {
        if (name[j] == '(') {
          if (!nested) {
            i = j;
            prei = i;
          }
          ++nested;
        } else if (name[j] == ')') {
          --nested;
          if (!nested) {
            ++j;
            break;
          }
        }
        ++j;
      }
      while (j < len) {
        name[i] = name[j];
        ++i;
        ++j;
      }
      name[i] = '\0';
      len = i;
      i = prei;
    }
  }
  return name;
}

char *demangle(const char *mangled_name) {
  char *demangled_name;
  int status;

  // ensure mangled_name is really mangled (start with "_Z")
  if (strncmp(mangled_name, "_Z", 2) == 0) {
    demangled_name = __cxa_demangle(mangled_name, NULL, NULL, &status);
    if (!status) {
      return simplify(demangled_name);
    }
  }

  return strdup(mangled_name);
}