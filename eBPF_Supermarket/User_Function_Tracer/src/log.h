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
#include <stdio.h>

/**
 * @brief 设置输出的颜色
 * @param[in] color 颜色控制符
 */
void log_color(const char* color);

/**
 * @brief 输出连续cnt个字符c
 * @param[in] c 字符
 * @param[in] cnt 个数
 */
void log_char(char c, int cnt);

/**
 * @brief 输出头部
 * @param[in] cpuid 是否输出cpu编号
 * @param[in] tid 是否输出线程编号
 * @param[in] timestamp 是否输出时间戳
 */
void log_header(int cpuid, int tid, int timestamp);

/**
 * @brief 输出分隔符
 * @details 分隔符为" | "
 */
void log_split();

/**
 * @brief 输出CPU编号
 * @param[in] cpuid CPU编号
 */
void log_cpuid(int cpuid);

/**
 * @brief 输出线程号
 * @param[in] tid 线程号
 */
void log_tid(int tid);

/**
 * @brief 输出线程号
 * @param[in] tid 线程号
 */
void log_timestamp(unsigned long long timestamp);

/**
 * @brief 输出时间及其单位
 * @param[in] ns 时间（单位纳秒）
 * @details 从[ns,us,ms,s,m,h]中选择合适的单位输出时间信息
 */
void log_duration(unsigned long long ns);

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

/**
 * @brief 输出到stderr
 */
#define LOG(fmt, ...)                    \
  do {                                   \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
  } while (0)

#define TERM_RED "\033[0;31m"
#define TERM_GREEN "\033[0;32m"
#define TERM_GRAY "\033[0;90m"
#define TERM_NC "\033[0m"

#endif  // UTRACE_LOG_H