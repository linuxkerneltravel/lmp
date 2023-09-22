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

int elf_head_begin(struct elf_head* elf, const char* filename) {
  assert(elf_version(EV_CURRENT) != EV_NONE);

  elf->fd = open(filename, O_RDONLY);
  if (elf->fd < 0) {
    return -1;
  }

  elf->e = elf_begin(elf->fd, ELF_C_READ_MMAP, NULL);
  assert(elf->e);

  if (elf_kind(elf->e) != ELF_K_ELF) {
    return -1;
  }
  if (!gelf_getehdr(elf->e, &elf->ehdr)) {
    return -1;
  }
  return 0;
}

void elf_head_end(struct elf_head* elf) {
  elf_end(elf->e);
  close(elf->fd);
}

size_t get_entry_address(struct elf_head* elf) { return elf->ehdr.e_entry; }

void elf_section_begin(struct elf_section* elf_s, struct elf_head* elf) {
  elf_getshdrstrndx(elf->e, &elf_s->str_idx);
  elf_s->scn = NULL;
}

int elf_section_next(struct elf_section* elf_s, struct elf_head* elf) {
  elf_s->scn = elf_nextscn(elf->e, elf_s->scn);
  return elf_s->scn && gelf_getshdr(elf_s->scn, &elf_s->shdr);
}

void elf_sym_entry_begin(struct elf_sym_entry* elf_e, struct elf_section* elf_s) {
  elf_e->i = 0;
  elf_e->num = elf_s->shdr.sh_size / elf_s->shdr.sh_entsize;
  elf_e->sym_data = elf_getdata(elf_s->scn, NULL);
  elf_e->str_idx = elf_s->shdr.sh_link;
}

int elf_sym_entry_next(struct elf_sym_entry* elf_e, struct elf_section* elf_s) {
  if ((elf_s->shdr.sh_type != SHT_DYNSYM && elf_s->shdr.sh_type != SHT_SYMTAB) ||
      elf_e->i >= elf_e->num)
    return 0;
  gelf_getsym(elf_e->sym_data, elf_e->i, &elf_e->sym);
  elf_e->i++;
  return 1;
}

void elf_rela_entry_begin(struct elf_rela_entry* elf_e, struct elf_section* elf_s,
                          Elf_Data* dyn_sym_data) {
  elf_e->i = 0;
  elf_e->num = elf_s->shdr.sh_size / elf_s->shdr.sh_entsize;
  elf_e->rela_data = elf_getdata(elf_s->scn, NULL);
  elf_e->sym_data = dyn_sym_data;
}

int elf_rela_entry_next(struct elf_rela_entry* elf_e, struct elf_section* elf_s) {
  if (elf_s->shdr.sh_type != SHT_RELA || elf_e->i >= elf_e->num) return 0;
  gelf_getrela(elf_e->rela_data, elf_e->i, &elf_e->rela);
  gelf_getsym(elf_e->sym_data, GELF_R_SYM(elf_e->rela.r_info), &elf_e->sym);
  elf_e->i++;
  return 1;
}