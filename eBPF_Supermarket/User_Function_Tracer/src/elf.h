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

#ifndef UTRACE_ELF_H
#define UTRACE_ELF_H

#include <gelf.h>
#include <stdbool.h>

/**
 * @brief represent an ELF header
 */
struct elf_head {
  int fd;         /**< ELF file descriptor */
  Elf *e;         /**< ELF pointer */
  GElf_Ehdr ehdr; /**< ELF header info */
};

/**
 * @brief init the given elf_head according to the file `filename`
 * @retval true on success
 */
bool elf_head_init(struct elf_head *elf, const char *filename);

/**
 * @brief free the elf_head
 */
void elf_head_free(struct elf_head *elf);

/**
 * @brief get the entry address of the program `filename`
 * @retval 0 on error
 * @details the entry address is recorded in ELF header
 */
size_t get_entry_address(const char *filename);

/**
 * @brief represent an ELF section
 */
struct elf_section {
  Elf_Scn *scn;   /**< ELF section info */
  GElf_Shdr shdr; /**< ELF section header info */
  size_t str_idx; /**< index in the string table */
};

// use the following functions like `for (elf_xxx_begin(...); elf_xxx_next(...); )`

/**
 * @brief begin to traverse each ELF section `elf_s`
 * @param[in] elf_s the ELF section to be assigned
 * @param[in] elf ELF header that contains `elf_s`
 */
void elf_section_begin(struct elf_section *elf_s, struct elf_head *elf);

/**
 * @brief move to next ELF section
 * @param[out] elf_s the next ELF section
 * @retval true when the current traversal ends, and the `elf_s` becomes undefined at this time
 */
bool elf_section_next(struct elf_section *elf_s, struct elf_head *elf);

/**
 * @brief represent an ELF symbol entry in .symtab section or .dynsym section
 */
struct elf_sym_entry {
  size_t i;
  size_t nentries;
  Elf_Data *sym_data;
  GElf_Sym sym;
  size_t str_idx;
};

/**
 * @brief begin to traverse each ELF symbol entry `elf_e`
 * @param[in] elf_e the ELF symbol entry to be assigned
 * @param[in] elf_s ELF section that contains `elf_e`
 */
void elf_sym_entry_begin(struct elf_sym_entry *elf_e, struct elf_section *elf_s);

/**
 * @brief move to next ELF symbol entry
 * @param[out] elf_e the next ELF symbol entry
 * @retval true when the current traversal ends, and the `elf_e` becomes undefined at this time
 */
bool elf_sym_entry_next(struct elf_sym_entry *elf_e, struct elf_section *elf_s);

/**
 * @brief represent an ELF relocation added entry in .rela section
 */
struct elf_rela_entry {
  size_t i;
  size_t nentries;
  Elf_Data *sym_data;
  Elf_Data *rela_data;
  GElf_Rela rela;
  GElf_Sym sym;
};

/**
 * @brief begin to traverse each ELF relocation added entry `elf_e`
 * @param[in] elf_e the ELF relocation added entry to be assigned
 * @param[in] elf_s ELF section that contains `elf_e`
 */
void elf_rela_entry_begin(struct elf_rela_entry *elf_e, struct elf_section *elf_s,
                          Elf_Data *dyn_sym_data);

/**
 * @brief move to next ELF relocation added entry
 * @param[out] elf_e the next ELF relocation added entry
 * @retval true when the current traversal ends, and the `elf_e` becomes undefined at this time
 */
bool elf_rela_entry_next(struct elf_rela_entry *elf_e, struct elf_section *elf_s);

/**
 * @brief represent an ELF relocation entry in .rel section
 */
struct elf_rel_entry {
  size_t i;
  size_t nentries;
  Elf_Data *sym_data;
  Elf_Data *rel_data;
  GElf_Rel rel;
  GElf_Sym sym;
};

/**
 * @brief begin to traverse each ELF relocation entry `elf_e`
 * @param[in] elf_e the ELF relocation entry to be assigned
 * @param[in] elf_s ELF section that contains `elf_e`
 */
void elf_rel_entry_begin(struct elf_rel_entry *elf_e, struct elf_section *elf_s,
                         Elf_Data *dyn_sym_data);

/**
 * @brief move to next ELF relocation entry
 * @param[out] elf_e the next ELF relocation entry
 * @retval true when the current traversal ends, and the `elf_e` becomes undefined at this time
 */
bool elf_rel_entry_next(struct elf_rel_entry *elf_e, struct elf_section *elf_s);

/**
 * @brief represent an ELF version symbol entry in .versym section
 */
struct elf_versym_entry {
  size_t i;
  size_t nentries;
  Elf_Data *versym_data;
  GElf_Versym versym;
};

/**
 * @brief begin to traverse each ELF version symbol entry `elf_e`
 * @param[in] elf_e the ELF version symbol entry to be assgined
 * @param[in] elf_s ELF section that contains `elf_e`
 */
void elf_versym_entry_begin(struct elf_versym_entry *elf_e, struct elf_section *elf_s);

/**
 * @brief move to next ELF version symbol entry
 * @param[out] elf_e the next ELF version symbol entry
 * @retval true when the current traversal ends, and the `elf_e` becomes undefined at this time
 */
bool elf_versym_entry_next(struct elf_versym_entry *elf_e, struct elf_section *elf_s);

/**
 * @brief represent an ELF version definition entry in .verdef section
 */
struct elf_verdef_entry {
  size_t i;
  size_t offset;
  Elf_Data *verdef_data;
  GElf_Verdef verdef;
  size_t str_idx;
};

/**
 * @brief begin to traverse each ELF version definition entry `elf_e`
 * @param[in] elf_e the ELF version definition entry to be assigned
 * @param[in] elf_s ELF section that contains `elf_e`
 */
void elf_verdef_entry_begin(struct elf_verdef_entry *elf_e, struct elf_section *elf_s);

/**
 * @brief move to next ELF version definition entry
 * @param[out] elf_e the next ELF version definition entry
 * @retval true when the current traversal ends, and the `elf_e` becomes undefined at this time
 */
bool elf_verdef_entry_next(struct elf_verdef_entry *elf_e, struct elf_section *elf_s);

/**
 * @brief represent an ELF version needs entry in .verneed section
 */
struct elf_verneed_entry {
  size_t i;
  size_t offset;
  Elf_Data *verneed_data;
  GElf_Verneed verneed;
  size_t str_idx;
};

/**
 * @brief begin to traverse each ELF version needs entry `elf_e`
 * @param[in] elf_e the ELF version needs entry to be assigned
 * @param[in] elf_s ELF section that contains `elf_e`
 */
void elf_verneed_entry_begin(struct elf_verneed_entry *elf_e, struct elf_section *elf_s);

/**
 * @brief move to next ELF version needs entry
 * @param[out] elf_e the next ELF version needs entry
 * @retval true when the current traversal ends, and the `elf_e` becomes undefined at this time
 */
bool elf_verneed_entry_next(struct elf_verneed_entry *elf_e, struct elf_section *elf_s);

#endif  // UTRACE_ELF_H
