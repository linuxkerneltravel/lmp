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

#ifndef UTRACE_ELF_H
#define UTRACE_ELF_H

#include <gelf.h>

/**
 * @brief 保存ELF头信息
 */
struct elf_head {
  int fd;         /**< 文件描述符 */
  Elf* e;         /**< ELF指针 */
  GElf_Ehdr ehdr; /**< ELF头 */
};

/**
 * @brief 根绝文件名初始化ELF头信息
 * @param[out] elf 待初始化的ELF头
 * @param[in] filename 文件名
 */
int elf_head_begin(struct elf_head* elf, const char* filename);

/**
 * @brief 在使用完ELF头信息后释放资源
 * @param[in] elf 经过elf_head_begin()初始化后的ELF头
 */
void elf_head_end(struct elf_head* elf);

/**
 * @brief 保存ELF节信息，包括节指针以及节头表
 */
struct elf_section {
  Elf_Scn* scn;   /**< ELF节 */
  GElf_Shdr shdr; /**< ELF节头 */
  size_t str_idx; /**< 字符串表序号 */
};

/**
 * @brief 开始遍历ELF的各个节
 * @param[out] elf_s 指向一个节
 * @param[in] elf 被遍历的ELF头信息
 */
void elf_section_begin(struct elf_section* elf_s, struct elf_head* elf);

/**
 * @brief 移动到下一个ELF节
 * @param[out] elf_s 指向一个节
 * @param[in] elf 被遍历的ELF头信息
 * @return 指示是否遍历结束
 * @retval 0 当前elf_s合法
 *            1 当前elf_s不合法，即遍历结束
 */
int elf_section_next(struct elf_section* elf_s, struct elf_head* elf);

/**
 * @brief 保存ELF符号条目
 */
struct elf_sym_entry {
  size_t i;           /**< 当前条目序号 */
  size_t num;         /**< 条目总数 */
  Elf_Data* sym_data; /**< 符号数据 */
  GElf_Sym sym;       /**< 符号表项 */
  size_t str_idx;     /**< 字符串表序号 */
};

/**
 * @brief 保存ELF重定位条目
 */
struct elf_rela_entry {
  size_t i;            /**< 当前条目序号 */
  size_t num;          /**< 条目总数 */
  Elf_Data* sym_data;  /**< 符号数据 */
  Elf_Data* rela_data; /**< 重定位数据 */
  GElf_Rela rela;      /**< 重定位表项 */
  GElf_Sym sym;        /**< 符号表项 */
};

/**
 * @brief 开始遍历ELF节（.symtab, .dynsym）中的各个条目
 * @param[out] elf_e 指向一个条目
 * @param[in] elf_s 被遍历的ELF节
 */
void elf_sym_entry_begin(struct elf_sym_entry* elf_e, struct elf_section* elf_s);

/**
 * @brief 移动到下一个ELF条目
 * @param[out] elf_e 指向一个条目
 * @param[in] elf_s 被遍历的ELF节信息
 * @return 指示是否遍历结束
 * @retval 0 当前elf_e合法
 *         1 当前elf_e不合法，即遍历结束
 */
int elf_sym_entry_next(struct elf_sym_entry* elf_e, struct elf_section* elf_s);

/**
 * @brief 开始遍历ELF节（.rela）中的各个条目
 * @param[out] elf_e 指向一个条目
 * @param[in] elf_s 被遍历的ELF节
 * @param[in] dyn_sym_data 动态符号数据
 */
void elf_rela_entry_begin(struct elf_rela_entry* elf_e, struct elf_section* elf_s,
                          Elf_Data* dyn_sym_data);

/**
 * @brief 移动到下一个ELF条目
 * @param[out] elf_e 指向一个条目
 * @param[in] elf_s 被遍历的ELF节信息
 * @return 指示是否遍历结束
 * @retval 0 当前elf_e合法
 *         1 当前elf_e不合法，即遍历结束
 */
int elf_rela_entry_next(struct elf_rela_entry* elf_e, struct elf_section* elf_s);

#endif  // UTRACE_ELF_H
