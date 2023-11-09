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
// Use gelf library to parse each section in an ELF file

#include "elf.h"

#include <fcntl.h>
#include <unistd.h>

bool elf_head_init(struct elf_head *elf, const char *filename) {
  if (elf_version(EV_CURRENT) == EV_NONE) return false;

  elf->fd = open(filename, O_RDONLY);
  if (elf->fd < 0) return false;

  elf->e = elf_begin(elf->fd, ELF_C_READ_MMAP, NULL);
  if (!elf->e) return false;

  if (elf_kind(elf->e) != ELF_K_ELF) return false;
  if (!gelf_getehdr(elf->e, &elf->ehdr)) return false;

  return true;
}

void elf_head_free(struct elf_head *elf) {
  if (elf) {
    elf_end(elf->e);
    close(elf->fd);
  }
}

size_t get_entry_address(const char *filename) {
  struct elf_head elf;
  if (!elf_head_init(&elf, filename)) return 0;
  size_t entry = elf.ehdr.e_entry;  // the entry address is recorded in ELF header
  elf_head_free(&elf);
  return entry;
}

void elf_section_begin(struct elf_section *elf_s, struct elf_head *elf) {
  elf_getshdrstrndx(elf->e, &elf_s->str_idx);
  elf_s->scn = NULL;
}

bool elf_section_next(struct elf_section *elf_s, struct elf_head *elf) {
  elf_s->scn = elf_nextscn(elf->e, elf_s->scn);
  return elf_s->scn && gelf_getshdr(elf_s->scn, &elf_s->shdr);
}

void elf_sym_entry_begin(struct elf_sym_entry *elf_e, struct elf_section *elf_s) {
  elf_e->i = 0;
  elf_e->nentries =
      elf_s->shdr.sh_size / elf_s->shdr.sh_entsize;  // number of entries in this section
  elf_e->sym_data = elf_getdata(elf_s->scn, NULL);
  elf_e->str_idx = elf_s->shdr.sh_link;
}

bool elf_sym_entry_next(struct elf_sym_entry *elf_e, struct elf_section *elf_s) {
  (void)elf_s;  // keep all functions' prototypes consistent
  if (elf_e->i >= elf_e->nentries) return false;
  gelf_getsym(elf_e->sym_data, elf_e->i, &elf_e->sym);
  elf_e->i++;
  return true;
}

void elf_rela_entry_begin(struct elf_rela_entry *elf_e, struct elf_section *elf_s,
                          Elf_Data *dyn_sym_data) {
  elf_e->i = 0;
  elf_e->nentries = elf_s->shdr.sh_size / elf_s->shdr.sh_entsize;
  elf_e->rela_data = elf_getdata(elf_s->scn, NULL);
  elf_e->sym_data = dyn_sym_data;
}

bool elf_rela_entry_next(struct elf_rela_entry *elf_e, struct elf_section *elf_s) {
  (void)elf_s;
  if (elf_e->i >= elf_e->nentries) return false;
  gelf_getrela(elf_e->rela_data, elf_e->i, &elf_e->rela);
  gelf_getsym(elf_e->sym_data, GELF_R_SYM(elf_e->rela.r_info), &elf_e->sym);
  elf_e->i++;
  return true;
}

void elf_rel_entry_begin(struct elf_rel_entry *elf_e, struct elf_section *elf_s,
                         Elf_Data *dyn_sym_data) {
  elf_e->i = 0;
  elf_e->nentries = elf_s->shdr.sh_size / elf_s->shdr.sh_entsize;
  elf_e->rel_data = elf_getdata(elf_s->scn, NULL);
  elf_e->sym_data = dyn_sym_data;
}

bool elf_rel_entry_next(struct elf_rel_entry *elf_e, struct elf_section *elf_s) {
  (void)elf_s;
  if (elf_e->i >= elf_e->nentries) return false;
  gelf_getrel(elf_e->rel_data, elf_e->i, &elf_e->rel);
  gelf_getsym(elf_e->sym_data, GELF_R_SYM(elf_e->rel.r_info), &elf_e->sym);
  elf_e->i++;
  return true;
}

void elf_versym_entry_begin(struct elf_versym_entry *elf_e, struct elf_section *elf_s) {
  elf_e->i = 0;
  elf_e->nentries = elf_s->shdr.sh_size / elf_s->shdr.sh_entsize;
  elf_e->versym_data = elf_getdata(elf_s->scn, NULL);
}

bool elf_versym_entry_next(struct elf_versym_entry *elf_e, struct elf_section *elf_s) {
  (void)elf_s;
  if (elf_e->i >= elf_e->nentries) return 0;
  gelf_getversym(elf_e->versym_data, elf_e->i, &elf_e->versym);
  elf_e->i++;
  return true;
}

void elf_verdef_entry_begin(struct elf_verdef_entry *elf_e, struct elf_section *elf_s) {
  elf_e->i = 0;
  elf_e->offset = 0;
  elf_e->verdef_data = elf_getdata(elf_s->scn, NULL);
  elf_e->str_idx = elf_s->shdr.sh_link;
}

bool elf_verdef_entry_next(struct elf_verdef_entry *elf_e, struct elf_section *elf_s) {
  if (elf_e->i >= elf_s->shdr.sh_info) return false;
  if (elf_e->i > 0) elf_e->offset += elf_e->verdef.vd_next;
  gelf_getverdef(elf_e->verdef_data, elf_e->offset, &elf_e->verdef);
  elf_e->i++;
  return true;
}

void elf_verneed_entry_begin(struct elf_verneed_entry *elf_e, struct elf_section *elf_s) {
  elf_e->i = 0;
  elf_e->offset = 0;
  elf_e->verneed_data = elf_getdata(elf_s->scn, NULL);
  elf_e->str_idx = elf_s->shdr.sh_link;
}

bool elf_verneed_entry_next(struct elf_verneed_entry *elf_e, struct elf_section *elf_s) {
  if (elf_e->i >= elf_s->shdr.sh_info) return false;
  gelf_getverneed(elf_e->verneed_data, elf_e->offset, &elf_e->verneed);
  elf_e->offset += elf_e->verneed.vn_next;
  elf_e->i++;
  return true;
}
