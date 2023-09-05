#include "module.h"

#include <stdlib.h>

struct module* module_init(char* name) {
  struct module* module = malloc(sizeof(module));
  module->name = name;
  module->symbol_table = NULL;
  return module;
}

void module_free(struct module* module) {
  free(module->name);
  free(module);
  module = NULL;
}

const char* module_get_name(struct module* module) { return module->name; }

struct symbol_table* module_get_symbol_table(struct module* module) {
  return module->symbol_table;
}