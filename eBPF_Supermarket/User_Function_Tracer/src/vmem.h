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
// Related to virtual memory region

#ifndef UTRACE_VMEM_H
#define UTRACE_VMEM_H

#include <sys/types.h>

#include "module.h"
#include "vector.h"

/**
 * @brief represents a virtual memory region
 */
struct vmem {
  size_t st_addr; /**< start address */
  size_t ed_addr; /**< end address */
  size_t offset;  /**< offset */

  struct module* module; /**< name of the program/shared lib corresponding to this vmem */
};

/**
 * @brief represents a virtual memory table consisting of contiguous vmem sorted by st_addr
 * @details stored in a dynamic array
 */
struct vmem_table {
  struct vector* vmem_vec; /**< vmem vector */
};

/**
 * @brief create a vmem table for the process corresponding to the input pid
 * @param[in] pid process ID
 * @return a vmem table
 * @details parse the virtual file "/proc/{{pid}}/maps"
 */
struct vmem_table* vmem_table_init(pid_t pid);

/**
 * @brief free the vmem table
 * @param[in] vmem_table initialized by function vmem_table_init
 */
void vmem_table_free(struct vmem_table* vmem_table);

size_t vmem_table_size(struct vmem_table* vmem_table);

const struct vmem* vmem_table_get(struct vmem_table* vmem_table, size_t index);

/**
 * @brief find the vmem that contains the input address
 * @param[in] vmem_table
 * @param[in] addr the address to be searched
 * @return the vmem that contains address
 * @retval struct vmem* when successful
 *         NULL when failed
 * @details binary search the vmem_table (O(log))
 */
const struct vmem* vmem_table_find(struct vmem_table* vmem_table, size_t addr);

const struct symbol* vmem_table_symbolize(struct vmem_table* vmem_table, size_t addr);

/**
 * @brief get the start address of the program to be observed
 * @param[in] vmem_table
 * @return start address
 * @details the program is at the lowest address, i.e., its vmem is at the begin of vmem_table
 */
size_t vmem_table_get_prog_st_addr(struct vmem_table* vmem_table);

/**
 * @brief get the program name to be observed
 * @param[in] vmem_table
 * @return name
 */
const char* vmem_table_get_prog_name(struct vmem_table* vmem_table);

#endif  // UTRACE_VMEM_H