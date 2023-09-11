#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char* resolve_full_path(const char* file) {
  static char full_path[MAX_PATH_LEN];

  if (access(file, F_OK) != 0) {
    char* search_paths[] = {getenv("PATH"), "/usr/bin:/usr/sbin"};
    for (unsigned long i = 0; i < ARRAY_SIZE(search_paths); i++) {
      if (!search_paths[i]) continue;
      char* path_token = strtok(search_paths[i], ":");
      while (path_token) {
        snprintf(full_path, sizeof(full_path), "%s/%s", path_token, file);
        if (!access(full_path, F_OK)) return strdup(full_path);
        path_token = strtok(NULL, ":");
      }
    }
    return NULL;
  } else {
    return file;
  }
}

const char* base_name(const char* file) {
  const char* base_file = strrchr(file, '/');
  if (!base_file)
    return file;
  else
    return base_file + 1;
}

bool is_library(const char* file) {
  if (strstr(file, ".so.")) return true;

  // Check file is end with ".so"
  size_t len = strlen(file);
  if (len < 3) return false;
  return !strcmp(file + len - 3, ".so");
}

unsigned long long strduration2ns(const char* duration) {
  static char* units[] = {
      "ns", "us", "ms", "s", "m", "h",
  };
  static unsigned long long limits[] = {
      1000, 1000, 1000, 1000, 60, 24, 0,
  };

  unsigned long long d = 0, t = 1;

  const char* unit = duration;
  while (*unit != '\0' && !isalpha(*unit)) {
    if (isdigit(*unit))
      d = d * 10 + (unsigned long long)(*unit - '0');
    else
      return 0;
    ++unit;
  }
  if (*unit == '\0') return 0;

  for (unsigned long i = 0; i < ARRAY_SIZE(units); i++) {
    if (!strcmp(unit, units[i])) {
      return d * t;
    }
    t *= limits[i];
  }
  return 0;
}