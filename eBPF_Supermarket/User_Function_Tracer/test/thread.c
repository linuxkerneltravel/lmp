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
// Test multi-threaded program

#include <assert.h>
#include <pthread.h>

static void *c(void *n) { return n; }

static void *b(void *n) { return c(n); }

static void *a(void *n) { return b(n); }

int main() {
  int i;
  void *v;
  int n = 10;
  pthread_t t[4];

  for (i = 0; i < 4; i++) pthread_create(&t[i], NULL, a, &n);
  for (i = 0; i < 4; i++) {
    pthread_join(t[i], &v);
  }

  assert(*(int *)v == n);
  return 0;
}
