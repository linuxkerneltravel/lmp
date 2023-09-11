#ifndef UTRACE_UTIL_H
#define UTRACE_UTIL_H

#include <stdbool.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define MAX_PATH_LEN 256

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

const char* resolve_full_path(const char* file);

const char* base_name(const char* file);

bool is_library(const char* file);

unsigned long long strduration2ns(const char* duration);

#endif  // UTRACE_UTIL_H