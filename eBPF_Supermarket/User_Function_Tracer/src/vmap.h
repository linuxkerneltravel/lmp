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
// 保存运行时的虚拟地址映射表

#ifndef UTRACE_VMAP_H
#define UTRACE_VMAP_H

#include <stddef.h>
#include <sys/types.h>

/**
 * @brief 表示一个虚拟内存映射条目
 */
struct vmap {
  size_t addr_st; /**< 起始虚拟地址 */
  size_t addr_ed; /**< 结束虚拟地址 */
  size_t offset;  /**< 虚拟地址偏移 */
  char* module;   /**< 进程/共享库名称（指向堆内存） */

  struct vmap* next; /**< 下一个条目 */
};

/**
 * @brief 创建一个新的虚拟内存映射条目
 * @details 在堆上申请空间
 */
static struct vmap* init_vmap(size_t addr_st, size_t addr_ed, size_t offset, char* module);

/**
 * @brief 表示一个虚拟内存映射表
 * @details 链表
 */
struct vmap_list {
  struct vmap* head; /**< 链表头节点 */

  const char* program; /**< 观测的程序名 */
  size_t prog_addr_st; /** 观测的程序的起始虚拟地址 */
};

/**
 * @brief 创建进程号为pid的虚拟内存映射表
 * @param[in] pid 进程号
 * @return 对应的虚拟内存表
 * @details 查看并记录虚拟文件/proc/pid/maps
 *          在堆上申请空间
 */
struct vmap_list* init_vmap_list(pid_t pid);

/**
 * @brief 释放一个虚拟内存映射表
 * @param[in] vmap_list 指向一个由new_vmap_list()创建的虚拟内存映射表
 * @details 先释放每个条目的内存，再释放表内存
 */
void free_vmap_list(struct vmap_list* vmap_list);

/**
 * @brief 根据一个虚拟内存映射表，查找虚拟地址addr所在的虚拟内存映射条目
 * @param[in] vmap_list 指向一个虚拟内存映射表
 * @param[in] addr 待查找的虚拟内存地址
 * @return 对应的虚拟内存映射条目
 * @retval struct vmap*
 *            NULL 失败
 */
struct vmap* get_vmap(struct vmap_list* vmap_list, size_t addr);

/**
 * @brief 获得进程在运行时的起始虚拟地址
 * @param[in] vmap_list 指向一个虚拟内存映射表
 * @return 起始地址
 */
size_t get_prog_addr_st(struct vmap_list* vmap_list);

/**
 * @brief 获得进程的名称
 * @param[in] vmap_list 指向一个虚拟内存映射表
 * @return 进程名称
 */
const char* get_program(struct vmap_list* vmap_list);

#endif  // UTRACE_VMAP_H