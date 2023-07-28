#ifndef UTRACE_VMAP_H
#define UTRACE_VMAP_H

#include <stddef.h>
#include <sys/types.h>

struct vmap {
  size_t addr_st;
  size_t addr_ed;
  size_t offset;
  char* libname;  // owner full_path

  struct vmap* next;
};

static struct vmap* new_vmap();

struct vmap_list {
  struct vmap* head;
};

struct vmap_list* new_vmap_list(pid_t pid);

void delete_vmap_list(struct vmap_list* vmaps);

struct vmap* find_vmap(struct vmap_list* vmaps, size_t addr);

#endif  // UTRACE_VMAP_H
