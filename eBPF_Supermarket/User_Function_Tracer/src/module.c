// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: jinyufeng2000@gmail.com
//
// Module

#include "module.h"

#include <stdlib.h>

struct module *module_init(char *name) {
  struct module *module = malloc(sizeof(module));
  module->name = name;
  module->symbol_table = NULL;
  return module;
}

void module_free(struct module *module) {
  if (module) {
    free(module->name);
    free(module);
    module = NULL;
  }
}

bool module_init_symbol_table(struct module *module) {
  module->symbol_table = symbol_table_init(module->name);
  return module->symbol_table != NULL;
}

const char *module_get_name(const struct module *module) { return module->name; }

struct symbol_table *module_get_symbol_table(const struct module *module) {
  return module->symbol_table;
}
