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
// 提供日志打印

#ifndef UTRACE_LOG_H
#define UTRACE_LOG_H

#include <stddef.h>

/**
 * @brief 输出cnt个字符c
 * @param[in] c 字符
 * @param[in] cnt 个数
 */
void print_char(char c, int cnt);

/**
 * @brief 输出头部
 */
void print_header();

/**
 * @brief 输出线程号
 * @param[in] tid 线程号
 */
void print_tid(int tid);

/**
 * @brief 根据参数打印合适时间单位
 * @param[in] ns 时间（单位纳秒）
 * @details 从[ns,us,ms,s,m,h]中选择合适的单位输出
 */
void print_time_unit(size_t ns);

/** 控制是否显示调试信息，在utrace.c中定义 */
extern int debug;

/**
 * @brief 输出调试信息
 * @details 包装了fprintf(stderr)函数的宏
 */
#define DEBUG(fmt, ...)                    \
  do {                                     \
    if (debug) {                           \
      fprintf(stderr, "[DEBUG] ");         \
      fprintf(stderr, fmt, ##__VA_ARGS__); \
    }                                      \
  } while (0)

/**
 * @brief 输出错误信息
 * @details 包装了fprintf(stderr)函数的宏
 */
#define ERROR(fmt, ...)                  \
  do {                                   \
    fprintf(stderr, "[ERROR] ");         \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
  } while (0)

#endif  // UTRACE_LOG_H
