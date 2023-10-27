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
// A module represents a program or a library that contains a symbol table

#ifndef UTRACE_MODULE_H
#define UTRACE_MODULE_H

#include "symbol.h"

struct module {
  char *name;                        /**< name of this module malloced from heap */
  struct symbol_table *symbol_table; /**< symbol table of this module */
};

/**
 * @brief create and init a module
 * @param[in] name module name
 * @return struct module malloced from heap
 */
struct module *module_init(const char *name);

/**
 * @brief free the `module`
 */
void module_free(struct module *module);

/**
 * @brief create and init the symbol table of the input `module`
 * @reval true on success
 * @details we may not need the symbol table for some modules (e.g., modules skipped by "--no-lib"),
 *          so we initialize the symbol table in a separate function rather than just in
 *          `module_init()`
 */
bool module_symbol_table_init(struct module *module);

/**
 * @brief get the name of the input `module`
 */
const char *module_get_name(const struct module *module);

/**
 * @brief get the symbol table of the input `module`
 */
struct symbol_table *module_get_symbol_table(const struct module *module);

#endif  // UTRACE_MODULE_H
