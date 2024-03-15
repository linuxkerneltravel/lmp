/*
 * Linux内核诊断工具--elf相关函数头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef _PERF_ELF_H__
#define _PERF_ELF_H__

#include <set>
#include <string>

#include "symbol.h"

#define BUILD_ID_SIZE 40
bool save_symbol_cache(std::set<symbol> &ss, const char *path);
bool load_symbol_cache(std::set<symbol> &ss, const char *path, const char *filename);

bool get_symbol_from_elf(std::set<symbol> &ss, const char *path);
bool search_symbol(const std::set<symbol> &ss, symbol &sym);
int filename__read_build_id(int pid, const char *mnt_ns_name, const char *filename, char *bf, size_t size);
#endif
