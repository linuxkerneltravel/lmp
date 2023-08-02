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
  size_t addr_st; /**< 起始物理地址 */
  size_t addr_ed; /**< 结束物理地址 */
  size_t offset;  /**< 虚拟地址偏移 */
  char* libname;  /**< 进程/共享库名称（指向堆内存） */

  struct vmap* next; /**< 下一个条目 */
};

/**
 * @brief 创建一个新的虚拟内存映射条目
 * @details 在堆上申请空间
 */
static struct vmap* new_vmap();

/**
 * @brief 表示一个虚拟内存映射表
 * @details 链表
 */
struct vmap_list {
  struct vmap* head; /**< 链表头节点 */
};

/**
 * @brief 创建进程号为pid的虚拟内存映射表
 * @param[in] pid 进程号
 * @return 对应的虚拟内存表
 * @details 查看并记录虚拟文件/proc/pid/maps
 *          在堆上申请空间
 */
struct vmap_list* new_vmap_list(pid_t pid);

/**
 * @brief 释放一个虚拟内存映射表
 * @param[in] vmaps 指向一个由new_vmap_list()创建的虚拟内存映射表
 * @details 先释放每个条目的内存，再释放表内存
 */
void delete_vmap_list(struct vmap_list* vmaps);

/**
 * @brief 根据一个虚拟内存映射表，查找虚拟地址addr所在的虚拟内存映射条目
 * @param[in] vmaps 指向一个虚拟内存映射表
 * @param[in] addr 待查找的虚拟内存地址
 * @return 对应的虚拟内存映射条目
 * @retval struct vmap*
 *            NULL 失败
 */
struct vmap* find_vmap(struct vmap_list* vmaps, size_t addr);

#endif  // UTRACE_VMAP_H
