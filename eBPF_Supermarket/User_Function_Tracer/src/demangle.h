#ifndef UTRACE_DEMANGLE_H
#define UTRACE_DEMANGLE_H

extern char *__cxa_demangle(const char *name, char *output, long *len, int *status);

// the return value needs to be freed
char *demangle(const char *mangled_name);

#endif  // UTRACE_DEMANGLE_H
