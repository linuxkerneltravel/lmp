#include <fcntl.h>
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

  return 0;
}

int main(int argc, char *argv[]) {
  sleep(2);

  int n = 4096;

  foo(n);
  return 0;
}
