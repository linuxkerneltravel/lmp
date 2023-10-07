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
// Related to symbols

#ifndef UTRACE_SYMBOL_H
#define UTRACE_SYMBOL_H

#include "vector.h"

/**
 * @brief represent a symbol
 */
struct symbol {
  size_t addr; /**< relative virtual address */
  size_t size; /**< symbol size */
  char *name;  /**< symbol name */
  char *libname;
};

/**
 * @brief represent a symbol table consisting of all the symbols sorting by addr
 * @details stored in a dynamic array
 */
struct symbol_table {
  struct vector *symbol_vec;
};

/**
 * @brief 新建并初始化一个库/进程对应的符号数组
 * @param[in] libname 库/进程名
 * @param[in] dyn_symset 观测进程的动态符号数组
 * @return 指向初始化后的符号数组
 * @details 解析libname对应的ELF格式中的.symtab节和.dynsym节
 *          如果是进程（lib = 0），将.dynsym节的符号加入到dyn_symset集合中
 *          是动态库（lib = 1），只解析在dyn_symset集合中的符号
 */
struct symbol_table *symbol_table_init(const char *module_name);

void symbol_table_free(struct symbol_table *symbol_table);

size_t symbol_table_size(const struct symbol_table *symbol_table);

const struct symbol *symbol_table_get(const struct symbol_table *symbol_table, size_t index);

/**
 * @brief 从一个符号数组中查找一个虚拟地址对应的符号名称
 * @param[in] symbols 指向符号数组的指针
 * @param[in] addr 待查找的虚拟地址
 * @return addr对应的符号名称
 */
const struct symbol *symbol_table_find(const struct symbol_table *symbol_table, size_t addr);

#endif  // UTRACE_SYMTAB_H
