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

#include "util.h"

#include <ctype.h>
#include <linux/limits.h>  // for macro PATH_MAX
#include <string.h>
#include <unistd.h>

char *restrcat(char *dest, const char *src) {
  // ensure `dest` has enough space
  dest = realloc(dest, (strlen(src) + strlen(dest) + 1) * sizeof(char));
  if (!dest) die("realloc");

  size_t i = strlen(dest);
  while (*src != '\0') dest[i++] = *src++;
  dest[i] = '\0';
  return dest;
}

char *resolve_full_path(const char *file) {
  static char full_path[PATH_MAX];

  const size_t file_len = strlen(file);
  const char *search_paths[] = { getenv("PATH"), "/usr/bin:/usr/sbin" };
  if (access(file, F_OK) != 0) {
    for (unsigned long i = 0; i < ARRAY_SIZE(search_paths); i++) {
      if (!search_paths[i]) continue;
      for (const char *path_token = search_paths[i]; path_token;
           path_token = strchr(path_token, ':')) {
        if (path_token[0] == ':') ++path_token;
        const char *next_token = strchr(path_token, ':');
        size_t path_len =
            (next_token ? next_token - path_token : strlen(path_token)) + 1 + file_len + 1;
        snprintf(full_path, path_len, "%s/%s", path_token, file);
        full_path[path_len] = '\0';
        if (!access(full_path, F_OK)) return strdup(full_path);
      }
    }
    return NULL;
  } else {
    return strdup(file);
  }
}

const char *base_name(const char *file) {
  const char *base_file = strrchr(file, '/');
  return base_file ? base_file + 1 : file;
}

bool is_library(const char *file) {
  // check `file` contains ".so." or is end with ".so"
  return strstr(file, ".so.") || !strncmp(file + strlen(file) - 3, ".so", 3);
}

const char *system_exec(const char *cmd) {
  static char buf[64];
  FILE *fp = popen(cmd, "r");
  int offset = 0;
  if (fp) {
    while (fgets(buf + offset, sizeof(buf), fp) != NULL) {
      int len = strlen(buf + offset);
      offset += len;
    }
    pclose(fp);
  }
  buf[offset] = '\0';
  return buf;
}

unsigned long long duration_str2ns(const char *duration) {
  static char *units[] = {
    "ns", "us", "ms", "s", "m", "h",
  };
  static unsigned long long limits[] = {
    1000, 1000, 1000, 1000, 60, 24, 0,
  };

  unsigned long long d = 0, t = 1;
  while (*duration != '\0' && !isalpha(*duration)) {
    if (isdigit(*duration))
      d = d * 10 + (unsigned long long)(*duration - '0');
    else
      return 0;
    ++duration;
  }
  if (*duration == '\0') return 0;

  for (unsigned long i = 0; i < ARRAY_SIZE(units); i++) {
    if (!strcmp(duration, units[i])) return d * t;
    t *= limits[i];
  }
  return 0;
}

size_t resolve_addr(size_t addr) {
  if (addr > 0x8048000) return addr - 0x8048000;  // 32-bit load addr
  if (addr > 0x400000) return addr - 0x400000;    // 64-bit load addr
  return addr;
}
