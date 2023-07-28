#include "demangle.h"

#include <stdlib.h>
#include <string.h>

#include "utrace.h"

char *demangle(const char *mangled_name) {
  char *original_name;
  long len = MAX_SYMBOL_LEN;
  int status;

  // mangled_name is not mangled C++ symbol
  if (mangled_name[0] != '_' || mangled_name[1] != 'Z') return strdup(mangled_name);

  __cxa_demangle(mangled_name, NULL, &len, &status);
  if (status < 0) return strdup(mangled_name);

  original_name = malloc(len);
  __cxa_demangle(mangled_name, original_name, &len, &status);

  return original_name;
}
