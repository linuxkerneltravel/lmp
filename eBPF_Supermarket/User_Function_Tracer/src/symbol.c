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
// Related to symbols

#include "symbol.h"

#include <stdlib.h>
#include <string.h>

#include "demangle.h"
#include "elf.h"
#include "log.h"
#include "util.h"
#include "vector.h"

static int symbol_addr_less(const void *lhs, const void *rhs) {
  const size_t addr1 = ((const struct symbol *)lhs)->addr;
  const size_t addr2 = ((const struct symbol *)rhs)->addr;

  return addr1 < addr2 ? -1 : (addr1 > addr2 ? 1 : 0);
}

static void symbol_free(void *symbol) {
  struct symbol *sym = symbol;
  free(sym->name);
  sym->name = NULL;
  free(sym->libname);
  sym->libname = NULL;
}

struct symbol_table *symbol_table_init(const char *module_name) {
  struct elf_head elf;
  if (!elf_head_init(&elf, module_name)) return NULL;

  struct symbol_table *symbol_table = malloc(sizeof(struct symbol_table));
  symbol_table->symbol_vec = vector_init(sizeof(struct symbol), symbol_free);
  vector_reserve(symbol_table->symbol_vec, 16);  // initial capability

  struct elf_section elf_s;
  size_t plt_section_st_addr = 0;
  // get the start address of PLT section
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (!plt_section_st_addr && elf_s.shdr.sh_type == SHT_PROGBITS) {
      char *shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (!strcmp(shstr, ".plt.sec")) plt_section_st_addr = elf_s.shdr.sh_offset;
    }
  }
  if (!plt_section_st_addr) {
    for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
      if (elf_s.shdr.sh_type != SHT_PROGBITS) continue;

      char *shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (!strcmp(shstr, ".plt")) {
        plt_section_st_addr = elf_s.shdr.sh_offset + 0x10;
        break;
      }
    }
  }

  struct vector *libs = vector_init(sizeof(char *), NULL);
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type == SHT_GNU_verdef) {
      struct elf_verdef_entry elf_e;

      int cnt = 0;
      const char *lib = NULL;
      for (elf_verdef_entry_begin(&elf_e, &elf_s); elf_verdef_entry_next(&elf_e, &elf_s);) {
        GElf_Verdaux verdaux;
        gelf_getverdaux(elf_e.verdef_data, elf_e.offset + elf_e.verdef.vd_aux, &verdaux);
        if (!cnt)
          lib = elf_strptr(elf.e, elf_e.str_idx, verdaux.vda_name);
        else
          vector_push_back(libs, &lib);
        ++cnt;
      }
    }
  }
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type == SHT_GNU_verneed) {
      struct elf_verneed_entry elf_e;

      for (elf_verneed_entry_begin(&elf_e, &elf_s); elf_verneed_entry_next(&elf_e, &elf_s);) {
        const char *lib = elf_strptr(elf.e, elf_e.str_idx, elf_e.verneed.vn_file);
        for (int i = 0; i < elf_e.verneed.vn_cnt; i++) {
          vector_push_back(libs, &lib);
        }
      }
    }
  }

  struct vector *poss = vector_init(sizeof(size_t), NULL);
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type == SHT_GNU_versym) {
      struct elf_versym_entry elf_e;

      for (elf_versym_entry_begin(&elf_e, &elf_s); elf_versym_entry_next(&elf_e, &elf_s);) {
        size_t pos = elf_e.versym;  // 0: *local*, 1: *global*
        if (pos & 0x8000) pos ^= 0x8000;
        vector_push_back(poss, &pos);
      }
    }
  }

  size_t dyn_str_idx = 0;
  Elf_Data *dyn_sym_data = NULL;
  struct symbol sym;
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type == SHT_DYNSYM) {
      char *shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (strcmp(shstr, ".dynsym")) continue;

      struct elf_sym_entry elf_e;
      for (elf_sym_entry_begin(&elf_e, &elf_s); elf_sym_entry_next(&elf_e, &elf_s);) {
        if (!dyn_sym_data) {
          dyn_str_idx = elf_e.str_idx;
          dyn_sym_data = elf_e.sym_data;
          break;
        }
      }
    }
  }

  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type == SHT_RELA && plt_section_st_addr && dyn_sym_data) {
      char *shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (strcmp(shstr, ".rela.plt")) continue;
      struct elf_rela_entry elf_e;

      size_t rela_st_addr = 0;
      for (elf_rela_entry_begin(&elf_e, &elf_s, dyn_sym_data);
           elf_rela_entry_next(&elf_e, &elf_s);) {
        if (!rela_st_addr || elf_e.rela.r_offset < rela_st_addr) {
          rela_st_addr = elf_e.rela.r_offset;
        }
      }
      for (elf_rela_entry_begin(&elf_e, &elf_s, dyn_sym_data);
           elf_rela_entry_next(&elf_e, &elf_s);) {
        if (!strlen(elf_strptr(elf.e, dyn_str_idx, elf_e.sym.st_name))) continue;
        sym.addr = plt_section_st_addr + (elf_e.rela.r_offset - rela_st_addr) / 0x8 * 0x10;
        sym.addr = resolve_addr(sym.addr);
        sym.size = elf_e.sym.st_size;
        if (sym.size > 0) {
          continue;
        }
        sym.name = demangle(elf_strptr(elf.e, dyn_str_idx, elf_e.sym.st_name));
        size_t pos = *((size_t *)vector_const_get(poss, elf_e.rela.r_info >> 32));
        if (pos >= 2) {
          sym.libname = strdup(*((const char **)(vector_const_get(libs, pos - 2))));
        } else {
          sym.libname = NULL;
        }
        vector_push_back(symbol_table->symbol_vec, &sym);
      }
    }

    if (elf_s.shdr.sh_type == SHT_REL && plt_section_st_addr && dyn_sym_data) {
      char *shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (strcmp(shstr, ".rel.plt")) continue;
      struct elf_rel_entry elf_e;

      int valid = 1;  // TODO
      for (elf_rel_entry_begin(&elf_e, &elf_s, dyn_sym_data); elf_rel_entry_next(&elf_e, &elf_s);) {
        if (!strlen(elf_strptr(elf.e, dyn_str_idx, elf_e.sym.st_name))) {
          valid = 0;
          break;
        }
      }
      if (valid) {
        size_t plt_entry_cnt = 0;
        for (elf_rel_entry_begin(&elf_e, &elf_s, dyn_sym_data);
             elf_rel_entry_next(&elf_e, &elf_s);) {
          sym.addr = plt_section_st_addr + plt_entry_cnt * 0x10;
          sym.addr = resolve_addr(sym.addr);
          ++plt_entry_cnt;
          sym.size = elf_e.sym.st_size;
          if (sym.size > 0) {
            continue;
          }
          sym.name = demangle(elf_strptr(elf.e, dyn_str_idx, elf_e.sym.st_name));
          size_t pos = *((size_t *)vector_const_get(poss, elf_e.rel.r_info >> 32));
          if (pos >= 2) {
            sym.libname = strdup(*((const char **)(vector_const_get(libs, pos - 2))));
          } else {
            sym.libname = NULL;
          }
          vector_push_back(symbol_table->symbol_vec, &sym);
        }
      }
    }

    if (elf_s.shdr.sh_type == SHT_SYMTAB) {
      char *shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (strcmp(shstr, ".symtab")) continue;

      struct elf_sym_entry elf_e;
      for (elf_sym_entry_begin(&elf_e, &elf_s); elf_sym_entry_next(&elf_e, &elf_s);) {
        if (GELF_ST_TYPE(elf_e.sym.st_info) != STT_FUNC &&
            GELF_ST_TYPE(elf_e.sym.st_info) != STT_GNU_IFUNC)
          continue;
        if (elf_e.sym.st_shndx == STN_UNDEF) continue;
        if (!elf_e.sym.st_size) continue;

        sym.addr = elf_e.sym.st_value;
        sym.addr = resolve_addr(sym.addr);
        sym.size = elf_e.sym.st_size;
        sym.name = demangle(elf_strptr(elf.e, elf_e.str_idx, elf_e.sym.st_name));
        sym.libname = NULL;
        vector_push_back(symbol_table->symbol_vec, &sym);
      }
    }
  }

  elf_head_free(&elf);
  vector_free(libs);
  vector_free(poss);

  vector_sort(symbol_table->symbol_vec, symbol_addr_less);
  vector_unique(symbol_table->symbol_vec, symbol_addr_less);

  {
    DEBUG("Symbols in %s:", module_name);
    for (size_t i = 0; i < vector_size(symbol_table->symbol_vec); i++) {
      const struct symbol *sym = vector_const_get(symbol_table->symbol_vec, i);
      if (sym->libname)
        DEBUG("[%zu] %lx %lx %s %s", i + 1, sym->addr, sym->size, sym->name, sym->libname);
      else
        DEBUG("[%zu] %lx %lx %s", i + 1, sym->addr, sym->size, sym->name);
    }
  }

  return symbol_table;
}

// assert symbol_table != NULL
void symbol_table_free(struct symbol_table *symbol_table) {
  if (symbol_table) {
    vector_free(symbol_table->symbol_vec);
    free(symbol_table);
  }
}

size_t symbol_table_size(const struct symbol_table *symbol_table) {
  return vector_size(symbol_table->symbol_vec);
}

const struct symbol *symbol_table_get(const struct symbol_table *symbol_table, size_t index) {
  return vector_get(symbol_table->symbol_vec, index);
}

static int symbol_addr_compare(const void *lhs, const void *rhs) {
  const struct symbol *sym = lhs;
  const size_t addr = *(const size_t *)rhs;

  if ((sym->size > 0 && sym->addr + sym->size <= addr) || (!sym->size && sym->addr < addr)) {
    return -1;
  } else if (sym->addr > addr) {
    return 1;
  } else {
    return 0;
  }
}

// assert symbol_table != NULL
const struct symbol *symbol_table_find(const struct symbol_table *symbol_table, size_t addr) {
  return vector_binary_search(symbol_table->symbol_vec, &addr, symbol_addr_compare);
}
