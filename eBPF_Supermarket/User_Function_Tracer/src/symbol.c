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
// 保存符号信息

#include "symbol.h"

#include <elf.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "demangle.h"
#include "elf.h"
#include "log.h"

static int addrsort(const void* lhs, const void* rhs) {
  const size_t addrl = ((const struct symbol*)(lhs))->addr;
  const size_t addrr = ((const struct symbol*)(rhs))->addr;

  if (addrl > addrr) return 1;
  if (addrl < addrr) return -1;
  return 0;
}

static int namesort(const void* lhs, const void* rhs) {
  const char** namel = (const char**)lhs;
  const char** namer = (const char**)rhs;
  return strcmp(*namel, *namer);
}

struct dyn_symbol_set* new_dyn_symbol_set() {
  struct dyn_symbol_set* dyn_symset = (struct dyn_symbol_set*)malloc(sizeof(struct dyn_symbol_set));
  dyn_symset->size = 0;
  dyn_symset->cap = 16;
  dyn_symset->names = (char**)malloc(dyn_symset->cap * sizeof(char*));
  return dyn_symset;
}

static void insert_dyn_symbol(struct dyn_symbol_set* dyn_symset, char* name) {
  if (dyn_symset->size == dyn_symset->cap) {
    dyn_symset->cap <<= 1;
    dyn_symset->names = (char**)realloc(dyn_symset->names, dyn_symset->cap * sizeof(char*));
  }
  dyn_symset->names[dyn_symset->size] = strdup(name);
  dyn_symset->size++;
}

static int contain_dyn_symbol(struct dyn_symbol_set* dyn_symset, char* name) {
  return (char*)bsearch(&name, dyn_symset->names, dyn_symset->size, sizeof(char*), namesort) !=
         NULL;
}

void delete_dyn_symbol_set(struct dyn_symbol_set* dyn_symset) {
  for (int i = 0; i < dyn_symset->size; i++) {
    free(dyn_symset->names[i]);
  }
  free(dyn_symset->names);
  free(dyn_symset);
}

struct symbol_arr* new_symbol_arr(char* libname, struct dyn_symbol_set* dyn_symset, int lib) {
  struct elf_head elf;
  elf_head_begin(&elf, libname);

  struct symbol_arr* symbols = (struct symbol_arr*)malloc(sizeof(struct symbol_arr));
  symbols->size = 0;
  symbols->cap = 16;  // NOTE
  symbols->sym = (struct symbol*)malloc(symbols->cap * sizeof(struct symbol));
  symbols->next = NULL;
  symbols->libname = strdup(basename(libname));
  struct elf_section elf_s;
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type != SHT_SYMTAB && elf_s.shdr.sh_type != SHT_DYNSYM) continue;
    struct elf_entry elf_e;
    struct symbol sym;
    size_t prev_sym_value = 0;
    for (elf_symbol_entry_begin(&elf_e, &elf_s); elf_symbol_entry_next(&elf_e, &elf_s);) {
      if (GELF_ST_TYPE(elf_e.sym.st_info) != STT_FUNC &&
          // GELF_ST_TYPE(elf_e.sym.st_info) != STT_OBJECT &&
          GELF_ST_TYPE(elf_e.sym.st_info) != STT_GNU_IFUNC)
        continue;

      sym.addr = elf_e.sym.st_value;
      sym.size = elf_e.sym.st_size;
      sym.name = elf_strptr(elf.e, elf_e.str_idx, elf_e.sym.st_name);
      sym.name = demangle(sym.name);

      if (!lib && elf_s.shdr.sh_type == SHT_DYNSYM) {
        insert_dyn_symbol(dyn_symset, sym.name);
        DEBUG("Dynamic symbol: %s\n", sym.name);
      }

      if (elf_e.sym.st_value == prev_sym_value) continue;
      if (elf_e.sym.st_shndx == STN_UNDEF) continue;
      if (sym.size == 0) continue;
      if (lib && !contain_dyn_symbol(dyn_symset, sym.name)) continue;

      push_symbol(symbols, &sym);
      prev_sym_value = elf_e.sym.st_value;
    }
  }
  elf_head_end(&elf);
  qsort(symbols->sym, symbols->size, sizeof(struct symbol), addrsort);
  if (!lib) qsort(dyn_symset->names, dyn_symset->size, sizeof(char*), namesort);

  DEBUG("Symbols in %s:\n", libname);
  int i = 0;
  for (struct symbol* sym = symbols->sym; sym != symbols->sym + symbols->size; sym++, i++) {
    DEBUG("[%d] %lx %lx %s\n", i + 1, sym->addr, sym->size, sym->name);
  }

  return symbols;
}

static void push_symbol(struct symbol_arr* symbols, struct symbol* symbol) {
  if (symbols->size == symbols->cap) {
    symbols->cap <<= 1;
    symbols->sym = (struct symbol*)realloc(symbols->sym, symbols->cap * sizeof(struct symbol));
  }
  symbols->sym[symbols->size] = *symbol;
  symbols->size++;
}

struct symbol_tab* new_symbol_tab() {
  struct symbol_tab* symtab = (struct symbol_tab*)malloc(sizeof(struct symbol_tab));
  symtab->head = NULL;
  return symtab;
}

void push_symbol_arr(struct symbol_tab* symbol_tab, struct symbol_arr* symbols) {
  symbols->next = symbol_tab->head;
  symbol_tab->head = symbols;
}

void delete_symbol_tab(struct symbol_tab* symbol_tab) {
  for (struct symbol_arr* symbols = symbol_tab->head; symbols != NULL;) {
    for (struct symbol* sym = symbols->sym; sym != symbols->sym + symbols->size; sym++) {
      free(sym->name);
    }
    free(symbols->sym);
    free(symbols->libname);
    struct symbol_arr* next_symbols = symbols->next;
    free(symbols);
    symbols = next_symbols;
  }
  free(symbol_tab);
}

char* find_symbol_name(struct symbol_arr* symbols, size_t addr) {
  for (struct symbol* sym = symbols->sym; sym != symbols->sym + symbols->size; sym++) {
    if (sym->addr <= addr && addr < sym->addr + sym->size) {
      return demangle(sym->name);
    }
  }
  return NULL;
}
