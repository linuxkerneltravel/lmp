#ifndef UTRACE_ELF_H
#define UTRACE_ELF_H

#include <gelf.h>

struct elf_head {
  int fd;
  Elf* e;
  GElf_Ehdr ehdr;
};

void elf_head_begin(struct elf_head* elf, const char* filename);

void elf_head_end(struct elf_head* elf);

struct elf_section {
  Elf_Scn* scn;
  GElf_Shdr shdr;
};

void elf_section_begin(struct elf_section* elf_s, struct elf_head* elf);

int elf_section_next(struct elf_section* elf_s, struct elf_head* elf);

struct elf_entry {
  size_t i;
  size_t num;
  Elf_Data* data;
  GElf_Sym sym;
  size_t str_idx;
};

void elf_symbol_entry_begin(struct elf_entry* elf_e, struct elf_section* elf_s);

int elf_symbol_entry_next(struct elf_entry* elf_e, struct elf_section* elf_s);

#endif  // UTRACE_ELF_H
