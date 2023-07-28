#ifndef UTRACE_SYMBOL_H
#define UTRACE_SYMBOL_H

#include <stddef.h>

#include "elf.h"

struct symbol {
  size_t addr;
  size_t size;
  char* name;  // owner
};

struct dyn_symbol_set {
  int size;
  int cap;
  char** names;
};

struct dyn_symbol_set* new_dyn_symbol_set();

static void insert_dyn_symbol(struct dyn_symbol_set* dyn_symset, char* name);

static int contain_dyn_symbol(struct dyn_symbol_set* dyn_symset, char* name);

void delete_dyn_symbol_set(struct dyn_symbol_set* dyn_symset);

struct symbol_arr {
  int size;
  int cap;
  struct symbol* sym;

  struct symbol_arr* next;
  char* libname;  // owner base_path
};

static void push_symbol(struct symbol_arr* symbols, struct symbol* symbol);

struct symbol_arr* new_symbol_arr(char* libname, struct dyn_symbol_set* dyn_symset, int lib);

struct symbol_tab {
  struct symbol_arr* head;
};

struct symbol_tab* new_symbol_tab();

void push_symbol_arr(struct symbol_tab* symbol_tab, struct symbol_arr* symbols);

void delete_symbol_tab(struct symbol_tab* symbol_tab);

char* find_symbol_name(struct symbol_arr* symbols, size_t addr);

#endif  // UTRACE_SYMTAB_H
