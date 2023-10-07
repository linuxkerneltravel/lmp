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
// demangle mangled C++ symbols

#include "demangle.h"

#include <stdio.h>  // for perror
#include <stdlib.h>
#include <string.h>

#include "util.h"

// simplify the demangled symbol name
static char *simplify(char *name) {
  size_t len = strlen(name);
  if (!len) return name;

  // remove function template "<...>"
  for (size_t i = 0; i < len; i++) {
    if (name[i] == '<') {
      if (name[i + 1] == '<' && i >= 8 &&
          strncmp(name + i - 8, "operator", 8) == 0) {  // skip operator<<
        i++;
        size_t j = i + 1;
        while (name[j] == ' ') ++j;
        memmove(name + i + 1, name + j, len - j + 1);
        len -= j - i - 1;
        continue;
      }
      size_t j = i;
      int nested = 1;
      while (j + 1 < len) {
        ++j;
        if (name[j] == '<') {
          ++nested;
        } else if (name[j] == '>') {
          --nested;
          if (!nested) break;
        }
      }
      memmove(name + i, name + j + 1, len - j);
      len -= j - i + 1;
    }
  }

  // remove function cv-qualifier
  for (size_t i = len - 1; i > 0; i--) {
    if (name[i] == ' ' && name[i - 1] == ')') {
      name[i] = '\0';
      len = i;
      break;
    }
  }

  // remove lambda function parameters, i.e., {lambda(...)}
  for (size_t i = 0; i < len; i++) {
    if (strncmp(name + i, "{lambda", 7) == 0) {
      i += 7;  // name[i] == '('
      size_t j = i;
      int nested = 1;
      while (j + 1 < len) {
        ++j;
        if (name[j] == '(') {
          ++nested;
        } else if (name[j] == ')') {
          --nested;
          if (!nested) break;
        }
      }
      memmove(name + i, name + j + 1, len - j);
      len -= j - i + 1;
      break;
    }
  }

  // remove function parameters, i.e., the last "(...)"
  for (size_t i = len - 1; i > 0; i--) {
    if (name[i] == ')') {
      size_t j = i;
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
      memmove(name + i, name + j + 1, len - j);
      len -= j - i + 1;
      // remove function return type
      for (j = i; j > 0; j--) {
        if (name[j] == ' ') {
          if (j != 8 || strncmp(name, "operator", 8)) {
            memmove(name, name + j + 1, len - j);
            len -= j + 1;
          }
          break;
        }
      }
      break;
    }
  }

  // remove trailing space
  while (len >= 1 && name[len - 1] == ' ') --len;

  return name;
}

char *demangle(const char *mangled_name) {
  const char *GLOBAL_PREFIX = "_GLOBAL__sub_I_";
  const size_t LEN = 15;

  char *demangled_name;
  size_t demangled_len;
  int status;
  size_t offset = 0;

  // handle symbols starting with GLOBAL_PREFIX introduced by <iostream>
  if (strncmp(mangled_name, GLOBAL_PREFIX, LEN) == 0) offset = LEN;

  // ensure mangled_name is really mangled (start with "_Z")
  if (strncmp(mangled_name + offset, "_Z", 2) == 0) {
    demangled_name = __cxa_demangle(mangled_name + offset, NULL, NULL, &status);
    if (!status) {
      demangled_name = simplify(demangled_name);
      demangled_len = strlen(demangled_name);
      if (offset > 0) {
        demangled_name = realloc(demangled_name, demangled_len + 1 + LEN);
        if (!demangled_name) die("realloc");
        memmove(demangled_name + LEN, demangled_name, demangled_len + 1);
        memcpy(demangled_name, GLOBAL_PREFIX, LEN);
      }
      return demangled_name;
    }
  }

  return strdup(mangled_name);
}
