#include <stdio.h>
#include <unistd.h>

void g() { sleep(2); }

void f() {
  g();
  sleep(1);
}

void h() { sleep(3); }

int main() {
  sleep(5);
  f();
  h();
  return 0;
}
