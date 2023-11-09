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
// demangle and simplify mangled C++ symbols

#include "demangle.h"

#include <string.h>

#include "util.h"

/**
 * @brief simplify the demangled symbol name
 */
static char *simplify(char *name) {
  size_t len = strlen(name);
  if (!len) return name;

  // remove all function templates, i.e., "<...>"
  for (size_t i = 0; i < len; i++) {
    if (name[i] == '<') {
      if (i >= 8 && !strncmp(name + i - 8, "operator", 8)) {  // skip `operator<` and `operator<<`
        if (name[i + 1] == '<') ++i;
        // remove useless extra blanks
        size_t j = i + 1;
        while (name[j] == ' ') ++j;
        memmove(name + i + 1, name + j, len - j + 1);
        len -= j - i - 1;
      } else {
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
  }

  // remove the last function cv-qualifier
  for (size_t i = len - 1; i > 0; i--) {
    if (name[i] == ')') break;
    if (name[i] == ' ' && name[i - 1] == ')') {
      name[len = i] = '\0';
      break;
    }
  }

  // remove all lambda function parameters, i.e., "{lambda(...)}"
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
    }
  }

  // remove all function parameters, i.e., "(...)"
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
      for (j = i - 1; j > 0; j--) {
        if (name[j] == ':' && name[j + 1] == ':') {  // there may be nested lambdas or namespaces
          i = j - 1;
          while (i > 0 && name[i] != ')' && name[i] != ':') --i;
          if (name[i] == ')') {
            if (!strncmp(name + i + 1, " const", 6)) {  // remove function cv-qualifier
              memmove(name + i + 1, name + j, len - j + 1);
              len -= j - i - 1;
            }
            break;
          }
        } else if (name[j] == ' ') {  // remove function return type at the beginning
          if (!(j == 8 && !strncmp(name, "operator", 8))) {
            memmove(name, name + j + 1, len - j);
            len -= j + 1;
          }
          i = 0;
          break;
        }
      }
      ++i;
    }
  }

  // remove trailing spaces
  while (len >= 1 && name[len - 1] == ' ') name[--len] = '\0';
  if (name[0] == '(' && name[len - 1] == ')') {
    memmove(name, name + 1, len);
    name[len - 2] = '\0';
    return simplify(name);
  }
  int st = 0;
  while (name[st] == '*' || name[st] == '&') ++st;
  if (st) memmove(name, name + st, len - st + 1);
  return name;
}

char *demangle(const char *mangled_name) {
  char *demangled_name;
  size_t demangled_len;
  int status;
  size_t offset = 0;

  // handle symbols starting with `GLOBAL_PREFIX` introduced by <iostream>
  const char *GLOBAL_PREFIX = "_GLOBAL__sub_I_";
  const size_t LEN = 15;
  if (!strncmp(mangled_name, GLOBAL_PREFIX, LEN)) offset = LEN;

  // ensure `mangled_name` is really mangled (start with "_Z")
  if (!strncmp(mangled_name + offset, "_Z", 2)) {
    demangled_name = __cxa_demangle(mangled_name + offset, NULL, NULL, &status);
    if (!status) {
      demangled_name = simplify(demangled_name);
      demangled_len = strlen(demangled_name);
      if (offset > 0) {  // concat `GLOBAL_PREFIX` with `demangled_name`
        demangled_name = realloc(demangled_name, demangled_len + 1 + LEN);
        if (!demangled_name) die("realloc");
        memmove(demangled_name + LEN, demangled_name, demangled_len + 1);  // keep the last '\0'
        memcpy(demangled_name, GLOBAL_PREFIX, LEN);
      }
      return demangled_name;
    }
  }

  return strdup(mangled_name);
}
