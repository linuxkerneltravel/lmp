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
// extended glob pattern match

#include "glob.h"

#include <stdlib.h>
#include <string.h>

/**
 * @brief regular glob match
 */
static bool glob_match(const char *text, const char *pattern) {
  bool matched;
  bool complemented;

  while (*text != '\0' && *pattern != '\0') {
    switch (*pattern) {
      case '?':  // match any single char
        ++pattern;
        ++text;
        break;

      case '*':
        if (glob_match(text, pattern + 1)) return true;  // non-greedy
        ++text;
        break;

      case '[':
        matched = false;
        complemented = false;

        ++pattern;
        if (*pattern == '!') {
          complemented = true;
          ++pattern;
        }
        if (*pattern == '\0') return false;

        char ch = *pattern;  // `ch` may be ']' or '-', just treat it normally
        matched |= (ch == *text);
        ++pattern;

        while (*pattern != ']') {
          switch (*pattern) {
            case '\0':
              return false;
            case '-':
              ++pattern;
              switch (*pattern) {
                case '\0':
                  return false;
                case ']':
                  matched |= ('-' == *text);
                  break;
                default:
                  matched |= (ch <= *text && *text <= *pattern);
                  ch = *pattern;
                  ++pattern;
              }
              break;
            default:
              ch = *pattern;
              matched |= (ch == *text);
              ++pattern;
          }
        }

        if (complemented) matched = !matched;
        if (!matched) return false;

        ++pattern;
        ++text;
        break;

      case '\\':
        ++pattern;
        if (*pattern == '\0') return false;

      default:
        if (*pattern == *text) {
          ++pattern;
          ++text;
        } else {
          return false;
        }
    }
  }

  if (*text == '\0') {
    while (*pattern == '*') ++pattern;
    if (*pattern == '\0') return true;
  }
  return false;
}

bool glob_match_ext(const char *text, const char *pattern) {
  char *dup_pattern = strdup(pattern);
  char *glob_pattern = strtok(dup_pattern, ",");
  bool matched = false;
  if (!glob_pattern) {  // pattern is empty
    matched = !strlen(text);
  } else {
    while (glob_pattern) {  // split `pattern` by ',', and try to match each regular glob_pattern
                            // with `text`
      if (glob_match(text, glob_pattern)) {
        matched = true;
        break;
      }
      glob_pattern = strtok(NULL, ",");
    }
  }
  free(dup_pattern);
  return matched;
}
