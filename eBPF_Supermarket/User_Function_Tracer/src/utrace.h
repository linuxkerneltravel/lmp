#ifndef UTRACE_UTRACE_H
#define UTRACE_UTRACE_H

#define MAX_SYMBOL_LEN 64
#define MAX_STACK_DEPTH 128
#define MAX_PATH_LEN 256

typedef unsigned long long stack_trace_t[MAX_STACK_DEPTH];

struct profile_record {
  unsigned int tid;
  unsigned long long duration_ns;

  unsigned int kstack_sz;
  stack_trace_t kstack;

  unsigned int ustack_sz;
  stack_trace_t ustack;

  int exit;
};

#endif  // UTRACE_UTRACE_H
