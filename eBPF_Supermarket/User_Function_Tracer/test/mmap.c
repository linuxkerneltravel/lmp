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
// Test library calls

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int foo(long sz) {
  int fd;
  void *ptr;

  fd = open("/dev/zero", O_RDONLY);
  ptr = mmap(NULL, sz, PROT_READ, MAP_ANON | MAP_PRIVATE, fd, 0);
  mprotect(ptr, sz, PROT_NONE);
  munmap(ptr, sz);
  close(fd);

  printf("Finish mmap.\n");

  return 0;
}

int main() {
  foo(4096);
  return 0;
}
