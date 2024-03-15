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
// author: luiyanbing@foxmail.com
//
// 用户态使用的宏

#ifndef STACK_ANALYZER_USER
#define STACK_ANALYZER_USER

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/eventfd.h>
#include <signal.h>
#include <unistd.h>

#include "sa_common.h"

/// @brief 检查错误，若错误成立则打印带原因的错误信息并使上层函数返回-1
/// @param cond 被检查的条件表达式
/// @param info 要打印的错误信息
#define CHECK_ERR(cond, ...)                         \
	if (cond)                                        \
	{                                                \
		fprintf(stderr, __VA_ARGS__);                \
		fprintf(stderr, " [%s]\n", strerror(errno)); \
		return -1;                                   \
	}

#include <stdlib.h>
/// @brief 检查错误，若错误成立则打印带原因的错误信息并退出
/// @param cond 被检查的条件表达式
/// @param info 要打印的错误信息
#define CHECK_ERR_EXIT(cond, ...)                    \
	if (cond)                                        \
	{                                                \
		fprintf(stderr, __VA_ARGS__);                \
		fprintf(stderr, " [%s]\n", strerror(errno)); \
		exit(EXIT_FAILURE);                          \
	}

#endif
