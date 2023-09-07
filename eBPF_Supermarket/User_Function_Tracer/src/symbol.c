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

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "demangle.h"
#include "elf.h"
#include "log.h"

#define BASE_ADDR 0x400000  // for no-pie option

static int symbol_addr_less(const void* lhs, const void* rhs) {
  const size_t addr1 = ((const struct symbol*)lhs)->addr;
  const size_t addr2 = ((const struct symbol*)rhs)->addr;

  if (addr1 < addr2) {
    return -1;
  } else if (addr1 > addr2) {
    return 1;
  } else {
    return 0;
  }
}

struct symbol_table* symbol_table_init(const char* module) {
  struct elf_head elf;
  if (elf_head_begin(&elf, module)) return NULL;

  struct symbol_table* symbol_table = malloc(sizeof(struct symbol_table));
  symbol_table->symbol_vec = vector_init(sizeof(struct symbol));
  vector_reserve(symbol_table->symbol_vec, 16);

  struct elf_section elf_s;
  size_t plt_section_st_addr = 0;
  // get the start address of PLT section
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type != SHT_PROGBITS) continue;

    char* shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
    if (!strcmp(shstr, ".plt.sec")) {
      plt_section_st_addr = elf_s.shdr.sh_offset;
      break;
    }
  }
  if (!plt_section_st_addr) {
    for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
      if (elf_s.shdr.sh_type != SHT_PROGBITS) continue;

      char* shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (!strcmp(shstr, ".plt")) {
        plt_section_st_addr = elf_s.shdr.sh_offset + 0x10;
        break;
      }
    }
  }

  struct symbol sym;
  size_t dyn_str_idx;
  Elf_Data* dyn_sym_data = NULL;
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type == SHT_DYNSYM) {
      char* shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (strcmp(shstr, ".dynsym")) continue;

      struct elf_sym_entry elf_e;
      for (elf_sym_entry_begin(&elf_e, &elf_s); elf_sym_entry_next(&elf_e, &elf_s);) {
        dyn_str_idx = elf_e.str_idx;
        dyn_sym_data = elf_e.sym_data;
        break;
      }
    }

    if (elf_s.shdr.sh_type == SHT_RELA && plt_section_st_addr) {
      char* shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (strcmp(shstr, ".rela.plt")) continue;

      struct elf_rela_entry elf_e;

      int valid = 1;  // TODO
      for (elf_rela_entry_begin(&elf_e, &elf_s, dyn_sym_data);
           elf_rela_entry_next(&elf_e, &elf_s);) {
        if (!strlen(elf_strptr(elf.e, dyn_str_idx, elf_e.sym.st_name))) {
          valid = 0;
          break;
        }
      }

      if (valid) {
        size_t plt_entry_cnt = 0;
        for (elf_rela_entry_begin(&elf_e, &elf_s, dyn_sym_data);
             elf_rela_entry_next(&elf_e, &elf_s);) {
          sym.addr = plt_section_st_addr + plt_entry_cnt * 0x10;
          if (sym.addr >= BASE_ADDR) {
            sym.addr -= BASE_ADDR;
          }
          ++plt_entry_cnt;
          sym.size = elf_e.sym.st_size;
          if (sym.size > 0) {
            continue;
          }
          sym.name = elf_strptr(elf.e, dyn_str_idx, elf_e.sym.st_name);
          sym.name = demangle(sym.name);
          vector_push_back(symbol_table->symbol_vec, &sym);
        }
      }
    }

    if (elf_s.shdr.sh_type == SHT_SYMTAB) {
      char* shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
      if (strcmp(shstr, ".symtab")) continue;

      struct elf_sym_entry elf_e;
      for (elf_sym_entry_begin(&elf_e, &elf_s); elf_sym_entry_next(&elf_e, &elf_s);) {
        if (GELF_ST_TYPE(elf_e.sym.st_info) != STT_FUNC &&
            GELF_ST_TYPE(elf_e.sym.st_info) != STT_GNU_IFUNC)
          continue;
        if (elf_e.sym.st_shndx == STN_UNDEF) continue;
        if (!elf_e.sym.st_size) continue;

        sym.addr = elf_e.sym.st_value;
        if (sym.addr >= BASE_ADDR) {
          sym.addr -= BASE_ADDR;
        }
        sym.size = elf_e.sym.st_size;
        sym.name = elf_strptr(elf.e, elf_e.str_idx, elf_e.sym.st_name);
        sym.name = demangle(sym.name);

        vector_push_back(symbol_table->symbol_vec, &sym);
      }
    }
  }

  elf_head_end(&elf);

  vector_sort(symbol_table->symbol_vec, symbol_addr_less);
  vector_unique(symbol_table->symbol_vec, symbol_addr_less);

  {
    DEBUG("Symbols in %s:\n", module);
    for (size_t i = 0; i < vector_size(symbol_table->symbol_vec); i++) {
      const struct symbol* sym = vector_const_get(symbol_table->symbol_vec, i);
      DEBUG("[%zu] %lx %lx %s\n", i + 1, sym->addr, sym->size, sym->name);
    }
  }

  return symbol_table;
}

// assert symbol_table != NULL
void symbol_table_free(struct symbol_table* symbol_table) {
  vector_free(symbol_table->symbol_vec);
  free(symbol_table);
}

size_t symbol_table_size(struct symbol_table* symbol_table) {
  return vector_size(symbol_table->symbol_vec);
}

const struct symbol* symbol_table_get(struct symbol_table* symbol_table, size_t index) {
  return vector_get(symbol_table->symbol_vec, index);
}

static int symbol_addr_compare(const void* lhs, const void* rhs) {
  const struct symbol* sym = lhs;
  const size_t addr = *(const size_t*)rhs;
  if ((sym->size && sym->addr + sym->size <= addr) || (!sym->size && sym->addr < addr)) {
    return -1;
  } else if (sym->addr > addr) {
    return 1;
  } else {
    return 0;
  }
}

// assert symbol_table != NULL
const struct symbol* symbol_table_find(struct symbol_table* symbol_table, size_t addr) {
  return vector_binary_search(symbol_table->symbol_vec, &addr, symbol_addr_compare);
}