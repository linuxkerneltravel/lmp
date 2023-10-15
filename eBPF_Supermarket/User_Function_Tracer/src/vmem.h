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
// Represent the virtual memory region of the traced program

#ifndef UTRACE_VMEM_H
#define UTRACE_VMEM_H

#include <sys/types.h>  // for pid_t

#include "module.h"
#include "vector.h"

/**
 * @brief represent one vmem entry
 */
struct vmem {
  size_t st_addr; /**< start address */
  size_t ed_addr; /**< end address */
  size_t offset;  /**< offset */

  struct module *module; /**< the corresponding module, i.e., the traced program or some library */
};

/**
 * @brief represent a virtual memory table consisting of contiguous vmem sorted by `vmem->st_addr`
 * @details stored in a dynamic array
 */
struct vmem_table {
  struct vector *vmem_vec; /**< vmem vector */
};

/**
 * @brief create and init a vmem table for the process corresponding to the input `pid`
 * @param[in] pid the process ID of the traced program
 * @return struct vmem_table malloced from heap
 * @details parse the virtual file "/proc/{{pid}}/maps"
 */
struct vmem_table *vmem_table_init(pid_t pid);

/**
 * @brief free the `vmem_table`
 */
void vmem_table_free(struct vmem_table *vmem_table);

/**
 * @brief get the number of vmem entries of the input `vmem_table`
 */
size_t vmem_table_size(const struct vmem_table *vmem_table);

/**
 * @brief get the `index`-th vmem entry of the input vmem table
 */
const struct vmem *vmem_table_get(const struct vmem_table *vmem_table, size_t index);

/**
 * @brief find the vmem entry that contains the input `addr`
 * @details binary search the vmem_table, O(\log n)
 */
const struct vmem *vmem_table_find(const struct vmem_table *vmem_table, size_t addr);

/**
 * @brief resolve the symbol corresponding to the input `addr`
 * @details first binary search in the vmem table to find the corresponding vmem entry,
 *          then binary search in the symbol table of this entry's module; O(\log n)
 */
const struct symbol *vmem_table_symbolize(const struct vmem_table *vmem_table, size_t addr);

/**
 * @brief get the load address of the traced program when running
 * @param[in] pid process ID of the traced program
 * @return load address
 */
size_t vmem_table_get_prog_load_addr(pid_t pid);

/**
 * @brief get the path of the traced program
 * @param[in] pid process ID of the traced program
 */
char *vmem_table_get_prog_name(pid_t pid);

#endif  // UTRACE_VMEM_H
