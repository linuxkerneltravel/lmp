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

#include "vmem.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "util.h"

#define VMEM_MAX_LEN 256

struct vmem_table* vmem_table_init(pid_t pid) {
  char buf[VMEM_MAX_LEN];
  snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);

  FILE* fp = fopen(buf, "r");
  if (fp == NULL) {
    ERROR("Cannot open %s\n", buf);
    return NULL;
  }

  struct vmem_table* vmem_table = malloc(sizeof(struct vmem_table));
  vmem_table->vmem_vec = vector_init(sizeof(struct vmem));

  struct vmem vmem;
  char prot[5];
  int dev_major, dev_minor, inode;

  while (fgets(buf, sizeof(buf), fp)) {
    if (sscanf(buf, "%zx-%zx %s %zx %x:%x %d %s\n", &vmem.st_addr, &vmem.ed_addr, prot,
               &vmem.offset, &dev_major, &dev_minor, &inode, buf) != 8)
      continue;
    if (strlen(buf) == 0 || buf[0] != '/') continue;

    vmem.module = NULL;
    if (!vector_empty(vmem_table->vmem_vec)) {  // merge consecutive vmem
      struct vmem* prev_vmem = vector_back(vmem_table->vmem_vec);
      if (!strcmp(module_get_name(prev_vmem->module), buf)) {
        if (prev_vmem->ed_addr == vmem.st_addr) {
          prev_vmem->ed_addr = vmem.ed_addr;
          continue;
        } else {
          vmem.module = prev_vmem->module;
        }
      }
    }

    if (!vmem.module) {
      vmem.module = module_init(strdup(buf));
    }
    vector_push_back(vmem_table->vmem_vec, &vmem);
  }

  fclose(fp);

  {
    DEBUG("Virtual memory map:\n");
    for (size_t i = 0; i < vector_size(vmem_table->vmem_vec); i++) {
      const struct vmem* vmem = vector_const_get(vmem_table->vmem_vec, i);
      DEBUG("[%zu] %zx-%zx %zx %s\n", i + 1, vmem->st_addr, vmem->ed_addr, vmem->offset,
            module_get_name(vmem->module));
    }
  }

  return vmem_table;
}

// assert vmem_table != NULL
void vmem_table_free(struct vmem_table* vmem_table) {
  vector_free(vmem_table->vmem_vec);
  free(vmem_table);
  vmem_table = NULL;
}

size_t vmem_table_size(struct vmem_table* vmem_table) { return vector_size(vmem_table->vmem_vec); }

const struct vmem* vmem_table_get(struct vmem_table* vmem_table, size_t index) {
  return vector_const_get(vmem_table->vmem_vec, index);
}

// assert type(lhs) is struct vmem* && type(rhs) is size_t*
static int vmem_addr_compare(const void* lhs, const void* rhs) {
  const struct vmem* vmem = lhs;
  const size_t addr = *(const size_t*)rhs;
  if (vmem->ed_addr < addr) {
    return -1;
  } else if (vmem->st_addr > addr) {
    return 1;
  } else {
    return 0;
  }
}

// assert vmem_table != NULL
const struct vmem* vmem_table_find(struct vmem_table* vmem_table, size_t addr) {
  return vector_binary_search(vmem_table->vmem_vec, &addr, vmem_addr_compare);
}

const struct symbol* vmem_table_symbolize(struct vmem_table* vmem_table, size_t addr) {
  const struct vmem* vmem = vmem_table_find(vmem_table, addr);
  if (!vmem) return NULL;
  return symbol_table_find(module_get_symbol_table(vmem->module),
                           addr - vmem->st_addr + vmem->offset);
}

// assert vmem_table != NULL && !vector_empty(vmem_table->vmem_vec)
size_t vmem_table_get_prog_st_addr(struct vmem_table* vmem_table) {
  return ((struct vmem*)vector_front(vmem_table->vmem_vec))->st_addr;
}

// assert vmem_table != NULL && !vector_empty(vmem_table->vmem_vec)
const char* vmem_table_get_prog_name(struct vmem_table* vmem_table) {
  return module_get_name(((struct vmem*)vector_front(vmem_table->vmem_vec))->module);
}