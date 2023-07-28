#ifndef UTRACE_LOG_H
#define UTRACE_LOG_H

#include <stddef.h>

void print_char(char c, int cnt);

void print_header();

void print_tid(int tid);

void print_time_unit(size_t ns);

extern int debug;
#define DEBUG(fmt, ...)                    \
  do {                                     \
    if (debug) {                           \
      fprintf(stderr, "[DEBUG] ");         \
      fprintf(stderr, fmt, ##__VA_ARGS__); \
    }                                      \
  } while (0)

#define ERROR(fmt, ...)                  \
  do {                                   \
    fprintf(stderr, "[ERROR] ");         \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
  } while (0)

#endif  // UTRACE_LOG_H