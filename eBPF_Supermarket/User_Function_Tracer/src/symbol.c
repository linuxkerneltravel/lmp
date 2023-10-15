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
// Maintain symbol tables for the traced program and its libraries

#include "symbol.h"

#include <string.h>

#include "demangle.h"
#include "elf.h"
#include "log.h"
#include "util.h"

/**
 * @brief sort by symbol addr in ascending order
 * @param[in] lhs struct symbol*
 * @param[in] rhs struct symbol*
 */
static int symbol_addr_less(const void *lhs, const void *rhs) {
  const size_t addr1 = ((const struct symbol *)lhs)->addr;
  const size_t addr2 = ((const struct symbol *)rhs)->addr;

  return addr1 < addr2 ? -1 : (addr1 > addr2 ? 1 : 0);
}

/**
 * @brief free the malloced `name` and `libname` in each symbol
 */
static void symbol_free(void *symbol) {
  struct symbol *sym = symbol;
  free(sym->name);
  free(sym->libname);
}

struct symbol_table *symbol_table_init(const char *module_name) {
  struct elf_head elf;
  if (!elf_head_init(&elf, module_name)) return NULL;

  struct symbol_table *symbol_table = malloc(sizeof(struct symbol_table));
  symbol_table->symbol_vec = vector_init(sizeof(struct symbol), symbol_free);
  vector_reserve(symbol_table->symbol_vec, 16);  // set initial capacity to 16

  struct elf_section elf_s;
  size_t plt_section_st_addr = 0;
  // get the start address of PLT section
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (!plt_section_st_addr && elf_s.shdr.sh_type == SHT_PROGBITS) {
      char *shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (!strcmp(shstr, ".plt.sec")) plt_section_st_addr = elf_s.shdr.sh_offset;
    }
  }
  // clang and musl-gcc does not have .plt.sec, then the PLT section is next to .plt
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (!plt_section_st_addr && elf_s.shdr.sh_type == SHT_PROGBITS) {
      char *shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (!strcmp(shstr, ".plt")) plt_section_st_addr = elf_s.shdr.sh_offset + 0x10;
    }
  }

  struct vector *libs = vector_init(sizeof(char **), NULL);
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type == SHT_GNU_verdef) {
      // .verdef is of the form like "libc.so.6 (lib), GLIBC_2.2.5, GLIBC_2.2.6, ...", we treat them
      // all as "libc.so.6"
      struct elf_verdef_entry elf_e;
      elf_verdef_entry_begin(&elf_e, &elf_s);
      elf_verdef_entry_next(&elf_e, &elf_s);
      GElf_Verdaux verdaux;
      gelf_getverdaux(elf_e.verdef_data, elf_e.offset + elf_e.verdef.vd_aux, &verdaux);
      const char *lib = elf_strptr(elf.e, elf_e.str_idx, verdaux.vda_name);
      do {
        vector_push_back(libs, &lib);
      } while (elf_verdef_entry_next(&elf_e, &elf_s));
    }
  }
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type == SHT_GNU_verneed) {
      // .verneed is of the form like "libc.so.6 (lib), GLIBC_2.14 3 (vna_other), GLIBC_2.2.5 2
      // (vna_other), ..."
      struct elf_verneed_entry elf_e;
      int cnt = 0;
      for (elf_verneed_entry_begin(&elf_e, &elf_s); elf_verneed_entry_next(&elf_e, &elf_s);)
        cnt += elf_e.verneed.vn_cnt;
      vector_resize(libs, vector_size(libs) + cnt);
      for (elf_verneed_entry_begin(&elf_e, &elf_s); elf_verneed_entry_next(&elf_e, &elf_s);) {
        const char *lib = elf_strptr(elf.e, elf_e.str_idx, elf_e.verneed.vn_file);
        int auxoffset = elf_e.offset + elf_e.verneed.vn_aux - elf_e.verneed.vn_next;
        for (int i = 0; i < elf_e.verneed.vn_cnt; i++) {
          GElf_Vernaux vernaux;
          gelf_getvernaux(elf_e.verneed_data, auxoffset, &vernaux);
          vector_set(libs, vernaux.vna_other - 2,
                     &lib);  // 0: *local*, 1: *global*; ignore these two
          auxoffset += vernaux.vna_next;
        }
      }
    }
  }
  struct vector *poss = vector_init(sizeof(size_t), NULL);
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type == SHT_GNU_versym) {
      struct elf_versym_entry elf_e;
      for (elf_versym_entry_begin(&elf_e, &elf_s); elf_versym_entry_next(&elf_e, &elf_s);) {
        size_t pos = elf_e.versym;
        if (pos & 0x8000) pos ^= 0x8000;  // ignore the difference between "@" and "@@"
        vector_push_back(poss, &pos);
      }
    }
  }

  Elf_Data *dyn_sym_data = NULL;
  size_t dyn_str_idx = 0;
  // extract the dynamic symbol data and its string table index for relocation entries
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type == SHT_DYNSYM) {
      char *shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (strcmp(shstr, ".dynsym")) continue;
      struct elf_sym_entry elf_e;
      for (elf_sym_entry_begin(&elf_e, &elf_s); elf_sym_entry_next(&elf_e, &elf_s);) {
        if (!dyn_sym_data) {
          dyn_sym_data = elf_e.sym_data;
          dyn_str_idx = elf_e.str_idx;
          break;
        }
      }
    }
  }

  struct symbol sym;
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    // 64-bit program has .rela.plt for library calls
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
        if (sym.size > 0) continue;
        // we need to do function name filtering, so demangle the symbol immediately
        sym.name = demangle(elf_strptr(elf.e, dyn_str_idx, elf_e.sym.st_name));
        size_t pos = *((size_t *)vector_const_get(poss, elf_e.rela.r_info >> 32));
        sym.libname =
            (pos < 2) ? NULL : strdup(*((const char **)(vector_const_get(libs, pos - 2))));
        vector_push_back(symbol_table->symbol_vec, &sym);
      }
    }

    // 32-bit program has .rel.plt for library calls
    if (elf_s.shdr.sh_type == SHT_REL && plt_section_st_addr && dyn_sym_data) {
      char *shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (strcmp(shstr, ".rel.plt")) continue;
      struct elf_rel_entry elf_e;
      size_t rel_st_addr = 0;
      for (elf_rel_entry_begin(&elf_e, &elf_s, dyn_sym_data); elf_rel_entry_next(&elf_e, &elf_s);) {
        if (!rel_st_addr || elf_e.rel.r_offset < rel_st_addr) {
          rel_st_addr = elf_e.rel.r_offset;
        }
      }
      for (elf_rel_entry_begin(&elf_e, &elf_s, dyn_sym_data); elf_rel_entry_next(&elf_e, &elf_s);) {
        if (!strlen(elf_strptr(elf.e, dyn_str_idx, elf_e.sym.st_name))) continue;
        sym.addr = plt_section_st_addr + (elf_e.rel.r_offset - rel_st_addr) / 0x4 * 0x10;
        sym.addr = resolve_addr(sym.addr);
        sym.size = elf_e.sym.st_size;
        if (sym.size > 0) continue;
        sym.name = demangle(elf_strptr(elf.e, dyn_str_idx, elf_e.sym.st_name));
        size_t pos = *((size_t *)vector_const_get(poss, elf_e.rel.r_info >> 32));
        sym.libname =
            (pos < 2) ? NULL : strdup(*((const char **)(vector_const_get(libs, pos - 2))));
        vector_push_back(symbol_table->symbol_vec, &sym);
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
  vector_unique(symbol_table->symbol_vec, symbol_addr_less);  // remove duplicate symbols

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

void symbol_table_free(struct symbol_table *symbol_table) {
  if (symbol_table) {
    vector_free(symbol_table->symbol_vec);
    free(symbol_table);
  }
}

// assert symbol_table != NULL
size_t symbol_table_size(const struct symbol_table *symbol_table) {
  return vector_size(symbol_table->symbol_vec);
}

// assert symbol_table != NULL
const struct symbol *symbol_table_get(const struct symbol_table *symbol_table, size_t index) {
  return vector_get(symbol_table->symbol_vec, index);
}

/**
 * @brief compare symbol's addr range [sym->addr, sym->addr + sym->size) (`lhs`) to an addr (`rhs`)
 * @param[in] lhs struct symbol*
 * @param[in] rhs size_t*
 * @details the size of dynamic symbols is 0, then compare `sym->addr` to the `addr` in this case
 */
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
