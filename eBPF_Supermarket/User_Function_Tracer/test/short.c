#include <stdio.h>

void h() {}
void g() { h(); }
void f() { g(); }

int main() {
  f();
  return 0;
}
