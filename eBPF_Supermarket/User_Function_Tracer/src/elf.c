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
// 解析ELF格式以遍历ELF中的各个节以及符号节中的各个条目

#include "elf.h"

#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

void elf_head_begin(struct elf_head* elf, const char* filename) {
  elf->fd = open(filename, O_RDONLY);
  assert(elf->fd >= 0);

  assert(elf_version(EV_CURRENT) != EV_NONE);

  elf->e = elf_begin(elf->fd, ELF_C_READ_MMAP, NULL);
  assert(elf->e);

  assert(gelf_getehdr(elf->e, &elf->ehdr));
}

void elf_head_end(struct elf_head* elf) {
  elf_end(elf->e);
  close(elf->fd);
}

void elf_section_begin(struct elf_section* elf_s, struct elf_head* elf) { elf_s->scn = NULL; }

int elf_section_next(struct elf_section* elf_s, struct elf_head* elf) {
  elf_s->scn = elf_nextscn(elf->e, elf_s->scn);
  return elf_s->scn && gelf_getshdr(elf_s->scn, &elf_s->shdr);
}

void elf_symbol_entry_begin(struct elf_entry* elf_e, struct elf_section* elf_s) {
  elf_e->i = 0;
  elf_e->num = elf_s->shdr.sh_size / elf_s->shdr.sh_entsize;
  elf_e->data = elf_getdata(elf_s->scn, NULL);
  elf_e->str_idx = elf_s->shdr.sh_link;
}

int elf_symbol_entry_next(struct elf_entry* elf_e, struct elf_section* elf_s) {
  if ((elf_s->shdr.sh_type != SHT_SYMTAB && elf_s->shdr.sh_type != SHT_DYNSYM) ||
      elf_e->i >= elf_e->num)
    return 0;
  gelf_getsym(elf_e->data, elf_e->i, &elf_e->sym);
  elf_e->i++;
  return 1;
}
