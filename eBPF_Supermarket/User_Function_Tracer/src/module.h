#ifndef UTRACE_MODULE_H
#define UTRACE_MODULE_H

#include "symbol.h"

struct module {
  char* name;
  struct symbol_table* symbol_table;
};

struct module* module_init(char* name);

void module_free(struct module* module);

const char* module_get_name(struct module* module);

struct symbol_table* module_get_symbol_table(struct module* module);

#endif  // UTRACE_MODULE_H