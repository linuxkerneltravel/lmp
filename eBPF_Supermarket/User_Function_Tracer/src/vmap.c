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
// 保存运行时的虚拟内存映射表

#include "vmap.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"

#define VMAP_ENTRY_MAX_LEN 256

static struct vmap *init_vmap(size_t addr_st, size_t addr_ed, size_t offset, char *module) {
  struct vmap *vmap = malloc(sizeof(struct vmap));
  vmap->addr_st = addr_st;
  vmap->addr_ed = addr_ed;
  vmap->offset = offset;
  vmap->module = strdup(module);
  vmap->next = NULL;
  return vmap;
}

struct vmap_list *init_vmap_list(pid_t pid) {
  char buf[VMAP_ENTRY_MAX_LEN];
  snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);

  FILE *fp = fopen(buf, "r");
  if (fp == NULL) {
    ERROR("Cannot open %s\n", buf);
    exit(1);
  }

  struct vmap_list *vmap_list = malloc(sizeof(struct vmap_list));
  vmap_list->head = NULL;

  size_t addr_st, addr_ed, offset;
  char prot[5];
  int dev_major, dev_minor, inode;
  char module[VMAP_ENTRY_MAX_LEN];

  while (fgets(buf, sizeof(buf), fp)) {
    if (sscanf(buf, "%zx-%zx %s %zx %x:%x %d %s\n", &addr_st, &addr_ed, prot, &offset, &dev_major,
               &dev_minor, &inode, module) != 8)
      continue;
    if (strlen(module) == 0 || module[0] != '/') continue;

    if (vmap_list->head != NULL && addr_st == vmap_list->head->addr_ed &&
        !strcmp(module, vmap_list->head->module)) {  // merge consecutive segments
      vmap_list->head->addr_ed = addr_ed;
    } else {
      struct vmap *vmap = init_vmap(addr_st, addr_ed, offset, module);
      if (vmap_list->head == NULL) {
        vmap_list->prog_addr_st = addr_st;
        vmap_list->program = vmap->module;
      }
      vmap->next = vmap_list->head;
      vmap_list->head = vmap;
    }
  }

  fclose(fp);

  DEBUG("Virtual memory map:\n");
  int i = 0;
  for (struct vmap *vmap = vmap_list->head; vmap != NULL; vmap = vmap->next, i++) {
    DEBUG("[%d] %zx-%zx %zx %s\n", i + 1, vmap->addr_st, vmap->addr_ed, vmap->offset, vmap->module);
  }

  return vmap_list;
}

void free_vmap_list(struct vmap_list *vmap_list) {
  struct vmap *vmap;
  struct vmap *next_vmap;
  for (vmap = vmap_list->head; vmap != NULL;) {
    next_vmap = vmap->next;
    free(vmap->module);
    free(vmap);
    vmap = next_vmap;
  }
  free(vmap_list);
}

struct vmap *get_vmap(struct vmap_list *vmap_list, size_t addr) {
  struct vmap *vmap;
  for (vmap = vmap_list->head; vmap != NULL; vmap = vmap->next) {
    if (vmap->addr_st <= addr && addr <= vmap->addr_ed) {
      return vmap;
    }
  }
  return NULL;
}

size_t get_prog_addr_st(struct vmap_list *vmap_list) { return vmap_list->prog_addr_st; }

const char *get_program(struct vmap_list *vmap_list) { return vmap_list->program; }