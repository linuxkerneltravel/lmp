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
