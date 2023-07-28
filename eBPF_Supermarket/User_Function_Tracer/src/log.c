#include "log.h"

#include <stdio.h>

void print_char(char c, int cnt) {
  while (cnt > 0) {
    printf("%c", c);
    --cnt;
  }
}

void print_header() { printf("# DURATION     TID     FUNCTION\n"); }

void print_tid(int tid) { printf("[%6d]", tid); }

void print_time_unit(size_t ns) {
  static char *units[] = {
      "ns", "us", "ms", " s", " m", " h",
  };
  static size_t limit[] = {
      1000, 1000, 1000, 1000, 60, 24, 0,
  };

  size_t t = ns, t_mod = 0;
  int i = 0;
  while (i < sizeof(units) / sizeof(units[0]) - 1) {
    if (t < limit[i]) break;
    t_mod = t % limit[i];
    t = t / limit[i];
    ++i;
  }

  printf("%3zu.%03zu %s", t, t_mod, units[i]);
}
