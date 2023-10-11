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

#include <linux/limits.h>  // for PATH_MAX
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "util.h"

static void vmem_free(void *vmem) {
  struct vmem *v = vmem;
  module_free(v->module);
}

struct vmem_table *vmem_table_init(pid_t pid) {
  char buf[PATH_MAX];
  snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);

  FILE *fp = fopen(buf, "r");
  if (!fp) die("fopen");

  struct vmem_table *vmem_table = malloc(sizeof(struct vmem_table));
  vmem_table->vmem_vec = vector_init(sizeof(struct vmem), vmem_free);

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
      struct vmem *prev_vmem = vector_back(vmem_table->vmem_vec);
      if (strcmp(module_get_name(prev_vmem->module), buf) == 0 &&
          prev_vmem->ed_addr == vmem.st_addr) {
        prev_vmem->ed_addr = vmem.ed_addr;
        continue;
      }
    }
    vmem.module = module_init(strdup(buf));
    vector_push_back(vmem_table->vmem_vec, &vmem);
  }

  fclose(fp);

  {
    DEBUG("Virtual memory map:");
    for (size_t i = 0; i < vector_size(vmem_table->vmem_vec); i++) {
      const struct vmem *vmem = vector_const_get(vmem_table->vmem_vec, i);
      DEBUG("[%zu] %zx-%zx %zx %s", i + 1, vmem->st_addr, vmem->ed_addr, vmem->offset,
            module_get_name(vmem->module));
    }
  }

  return vmem_table;
}

// assert vmem_table != NULL
void vmem_table_free(struct vmem_table *vmem_table) {
  if (vmem_table) {
    vector_free(vmem_table->vmem_vec);
    free(vmem_table);
  }
}

size_t vmem_table_size(const struct vmem_table *vmem_table) {
  return vector_size(vmem_table->vmem_vec);
}

const struct vmem *vmem_table_get(const struct vmem_table *vmem_table, size_t index) {
  return vector_const_get(vmem_table->vmem_vec, index);
}

// assert type(lhs) is struct vmem* && type(rhs) is size_t*
static int vmem_addr_compare(const void *lhs, const void *rhs) {
  const struct vmem *vmem = lhs;
  const size_t addr = *(const size_t *)rhs;

  return vmem->ed_addr < addr ? -1 : (vmem->st_addr > addr ? 1 : 0);
}

// assert vmem_table != NULL
const struct vmem *vmem_table_find(const struct vmem_table *vmem_table, size_t addr) {
  return vector_binary_search(vmem_table->vmem_vec, &addr, vmem_addr_compare);
}

const struct symbol *vmem_table_symbolize(const struct vmem_table *vmem_table, size_t addr) {
  const struct vmem *vmem = vmem_table_find(vmem_table, addr);
  if (!vmem) return NULL;
  return symbol_table_find(module_get_symbol_table(vmem->module),
                           addr - vmem->st_addr + vmem->offset);
}

// assert vmem_table != NULL && !vector_empty(vmem_table->vmem_vec)
size_t vmem_table_get_prog_load_addr(pid_t pid) {
  char buf[32];
  snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);

  FILE *fp = fopen(buf, "r");
  if (!fp) die("fopen");

  fgets(buf, sizeof(buf), fp);
  size_t load_addr = 0;
  sscanf(buf, "%zx", &load_addr);
  return load_addr;
}

// assert vmem_table != NULL && !vector_empty(vmem_table->vmem_vec)
char *vmem_table_get_prog_name(pid_t pid) {
  char buf[32];
  snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);

  FILE *fp = fopen(buf, "r");
  if (!fp) die("fopen");

  fgets(buf, sizeof(buf), fp);
  int i = strlen(buf) - 1;
  buf[i] = '\0';
  while (i >= 0) {
    if (buf[i] == ' ') break;
    --i;
  }
  return strdup(buf + i + 1);
}
