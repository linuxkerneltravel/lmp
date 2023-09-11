#include "util.h"

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