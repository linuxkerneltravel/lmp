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
// Maintain symbol tables for the traced program and its libraries

#ifndef UTRACE_SYMBOL_H
#define UTRACE_SYMBOL_H

#include "vector.h"

/**
 * @brief represent a symbol
 */
struct symbol {
  size_t addr;   /**< offset */
  size_t size;   /**< symbol size */
  char *name;    /**< symbol name malloced from heap */
  char *libname; /**< library name malloced from heap */
};

/**
 * @brief represent a symbol table consisting of all the symbols sorting by `addr`
 * @details stored in a dynamic array
 */
struct symbol_table {
  struct vector *symbol_vec;
};

/**
 * @brief create and init a symbol table for the module named `module_name`
 * @return struct symbol_table malloced from heap
 * @details parse its ELF file: get symbol info from sections .symtab, .dynsym, .rela and .rel; and
 *          get corresponding library info from sections .versym, .verdef and .verneed
 */
struct symbol_table *symbol_table_init(const char *module_name);

/**
 * @brief free the `symbol_table`
 */
void symbol_table_free(struct symbol_table *symbol_table);

/**
 * @brief get the number of symbols of the input `symbol_table`
 */
size_t symbol_table_size(const struct symbol_table *symbol_table);

/**
 * @brief get the `index`-th symbol of the input `symbol_table`
 */
const struct symbol *symbol_table_get(const struct symbol_table *symbol_table, size_t index);

/**
 * @brief find the symbol that corresponds to the input `addr`
 * @details binary search the `symbol_table`, O(\log n)
 */
const struct symbol *symbol_table_find(const struct symbol_table *symbol_table, size_t addr);

#endif  // UTRACE_SYMTAB_H
