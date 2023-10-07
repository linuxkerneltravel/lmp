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
// Test performance

#include <chrono>
#include <cstdio>

int g;

void f(int i) {
  if (i & 1)
    g += 1;
  else
    g += 2;
}

int main() {
  const int CNT = 1000000;
  auto start_time = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < CNT; i++) f(i);
  auto end_time = std::chrono::high_resolution_clock::now();
  printf("%d\n", g);
  std::chrono::nanoseconds elapsed_time =
      std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
  printf("total %f ms\naverage %f ns\n", elapsed_time.count() * 1.0 / 1000000,
         elapsed_time.count() * 1.0 / CNT);
}
