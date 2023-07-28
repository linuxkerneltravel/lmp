#include "vmap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "utrace.h"

static struct vmap *new_vmap() {
  struct vmap *v = (struct vmap *)malloc(sizeof(struct vmap));
  v->next = NULL;
  return v;
}

struct vmap_list *new_vmap_list(pid_t pid) {
  static char buf[MAX_PATH_LEN];
  snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);

  FILE *fmap = fopen(buf, "r");
  if (fmap == NULL) {
    ERROR("Cannot open %s\n", buf);
    exit(1);
  }

  size_t addr_st, addr_ed, offset;
  char prot[5];
  int dev_major, dev_minor, inode;
  char libname[MAX_PATH_LEN];

  struct vmap_list *vmaps = (struct vmap_list *)malloc(sizeof(struct vmap_list));
  vmaps->head = NULL;

  struct vmap *prev_vmap = NULL;
  while (fgets(buf, sizeof(buf), fmap)) {
    if (sscanf(buf, "%zx-%zx %s %zx %x:%x %d %s\n", &addr_st, &addr_ed, prot, &offset, &dev_major,
               &dev_minor, &inode, libname) != 8)
      continue;
    if (strlen(libname) == 0 || libname[0] == '[') continue;
    if (prev_vmap != NULL && addr_st == prev_vmap->addr_ed &&
        strcmp(libname, prev_vmap->libname) == 0) {
      prev_vmap->addr_ed = addr_ed;
    } else {
      struct vmap *vmap = new_vmap();
      vmap->addr_st = addr_st;
      vmap->addr_ed = addr_ed;
      vmap->offset = offset;
      vmap->libname = strdup(libname);
      if (prev_vmap)
        prev_vmap->next = vmap;
      else
        vmaps->head = vmap;
      prev_vmap = vmap;
    }
  }

  fclose(fmap);

  DEBUG("Virtual memory map:\n");
  int i = 0;
  for (struct vmap *vmap = vmaps->head; vmap != NULL; vmap = vmap->next, i++) {
    DEBUG("[%d] %zx-%zx %zx %s\n", i + 1, vmap->addr_st, vmap->addr_ed, vmap->offset,
          vmap->libname);
  }

  return vmaps;
}

void delete_vmap_list(struct vmap_list *vmaps) {
  for (struct vmap *vmap = vmaps->head; vmap != NULL;) {
    struct vmap *next_vmap = vmap->next;
    free(vmap->libname);
    free(vmap);
    vmap = next_vmap;
  }
  free(vmaps);
}

struct vmap *find_vmap(struct vmap_list *vmaps, size_t addr) {
  for (struct vmap *vmap = vmaps->head; vmap != NULL; vmap = vmap->next) {
    if (vmap->addr_st <= addr && addr <= vmap->addr_ed) {
      return vmap;
    }
  }
  return NULL;
}
