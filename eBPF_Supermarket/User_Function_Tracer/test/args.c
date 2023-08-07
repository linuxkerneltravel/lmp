#include <stdio.h>
#include <string.h>
#include <unistd.h>

void foobar() {}

void foo() {}

void bar() {
  foobar();
  foobar();
}

void tf1() {}

void tf2() {}

void arg_int3(int x, int y, int z) {
  /*
      printf("&x: %p\n", &x);
      printf("&y: %p\n", &y);
      printf("&z: %p\n", &z);
  */
}
void arg_int2(int a, int b) { arg_int3(a, b, b + 1); }
void arg_int1(int i) { arg_int2(i, i + 1); }

void arg_uint3(unsigned int x, unsigned int y, unsigned int z) {}
void arg_uint2(unsigned int a, unsigned int b) { arg_uint3(a, b, b + 1); }
void arg_uint1(unsigned int i) { arg_uint2(i, i + 1); }

void arg_char3(char x, char y, char z) {}
void arg_char2(char a, char b) { arg_char3(a, b, b + 1); }
void arg_char1(char i) { arg_char2(i, i + 1); }

void arg_short3(short x, short y, short z) {}
void arg_short2(short a, short b) { arg_short3(a, b, b + 1); }
void arg_short1(short i) { arg_short2(i, i + 1); }

void arg_long3(long x, long y, long z) {}
void arg_long2(long a, long b) { arg_long3(a, b, b + 1); }
void arg_long1(long i) { arg_long2(i, i + 1); }
void arg_ulong3(unsigned long x, unsigned long y, unsigned long z) {}
void arg_ulong2(unsigned long a, unsigned long b) { arg_ulong3(a, b, b + 1); }
void arg_ulong1(long i) { arg_ulong2(i, i + 1); }

void arg_longlong3(long long x, long long y, long long z) {}
void arg_longlong2(long long a, long long b) { arg_longlong3(a, b, b + 1); }
void arg_longlong1(long long i) { arg_longlong2(i, i + 1); }
void arg_ulonglong3(unsigned long long x, unsigned long long y, unsigned long long z) {}
void arg_ulonglong2(unsigned long long a, unsigned long long b) { arg_ulonglong3(a, b, b + 1); }
void arg_ulonglong1(unsigned long long i) { arg_ulonglong2(i, i + 1); }

void arg_test(int x, char *z) {}

int main(int argc, char *argv[]) {
  sleep(2);
  arg_int1(10);
  arg_uint1(10);
  arg_char1(20);
  arg_short1(30);
  arg_long1(40);
  arg_ulong1(50);
  arg_longlong1(60);
  arg_ulonglong1(70);
  arg_test(100, NULL);
  return 0;
}
