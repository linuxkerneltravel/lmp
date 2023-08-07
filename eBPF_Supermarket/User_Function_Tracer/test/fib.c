#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int fib(int n) {
  if (n <= 2) return 1;
  return fib(n - 1) + fib(n - 2);
}

int main() {
  sleep(2);
  int n = 8;

  return !!fib(n);
}
