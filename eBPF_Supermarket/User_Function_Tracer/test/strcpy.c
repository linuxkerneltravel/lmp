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
// Test library calls, involving GNU ifunc calls

#include <stdlib.h>
#include <string.h>

int main() {
  char *s = "Hello!";
  char *t = malloc(15 * sizeof(char));
  int m = strlen(s);
  memcpy(t, s, m);
  int n = strlen(t);
  int ss = strlen(s) + strlen(t);
  memset(t, 0, n);
  free(t);
  t = malloc(12 * sizeof(char));
  free(t);
  return 0;
}
