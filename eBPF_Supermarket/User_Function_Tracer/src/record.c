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
// Record the traced data

#include "record.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "util.h"

struct record *record_init(pid_t pid) {
  struct record *record = malloc(sizeof(struct record));
  record->out = fopen("./utrace.data", "wb");
  if (!record->out) die("fopen");
  record->pid = pid;
  return record;
}

/**
 * @brief write a string to file
 * @param[in] str the string
 * @param[in] fp point to the file to be written
 * @details len (size_t) + str (const char *[])
 */
static void fwrite_str(const char *str, FILE *fp) {
  size_t len = strlen(str);
  fwrite(&len, sizeof(size_t), 1, fp);
  fwrite(str, sizeof(char), strlen(str), fp);
}

void record_header(struct record *record, int argc, char **argv) {
  time_t t;
  time(&t);
  char *cur_time = ctime(&t);
  cur_time[strlen(cur_time) - 1] = '\0';  // overwrite the last '\n'
  fwrite_str(cur_time, record->out);
  char *cmdline = strdup(argv[0]);
  for (int i = 1; i < argc; i++) {
    cmdline = restrcat(cmdline, " ");
    cmdline = restrcat(cmdline, argv[i]);
  }
  fwrite_str(cmdline, record->out);
  free(cmdline);
  fwrite(&record->pid, sizeof(record->pid), 1, record->out);
}

void record_entry(struct record *record, struct user_record *user_record) {
  fwrite(&user_record->krecord.tid, sizeof(user_record->krecord.tid), 1, record->out);
  fwrite(&user_record->krecord.timestamp, sizeof(user_record->krecord.timestamp), 1, record->out);
  // we can compute `ustack_sz` and `duration_ns`, so we do not record them
  fwrite_str(user_record->name, record->out);
  fwrite_str(user_record->libname ? user_record->libname : "", record->out);
  fwrite(&user_record->krecord.ret, sizeof(user_record->krecord.ret), 1, record->out);
}

void record_free(struct record *record) {
  if (record) {
    fclose(record->out);
    free(record);
  }
}
