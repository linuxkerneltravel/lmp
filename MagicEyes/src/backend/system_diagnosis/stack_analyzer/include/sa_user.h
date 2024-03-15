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

#include <linux/version.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/eventfd.h>
#include <signal.h>
#include <unistd.h>

#include "sa_common.h"

struct Scale {
	const char *Type, *Unit;
	int64_t Period;
};

/// @brief 获取epbf程序中指定表的文件描述符
/// @param name 表的名字
#define OPEN_MAP(name) bpf_map__fd(skel->maps.name)

/// @brief 获取所有表的文件描述符
#define OPEN_ALL_MAP()               \
	value_fd = OPEN_MAP(psid_count); \
	tgid_fd = OPEN_MAP(pid_tgid);    \
	comm_fd = OPEN_MAP(pid_comm);    \
	trace_fd = OPEN_MAP(stack_trace);

/// @brief 加载、初始化参数并打开指定类型的ebpf程序
/// @param ... 一些ebpf程序全局变量初始化语句
/// @note 失败会使上层函数返回-1
#define StackProgLoadOpen(...)                     \
	skel = skel->open(NULL);                       \
	CHECK_ERR(!skel, "Fail to open BPF skeleton"); \
	skel->bss->min = min;                          \
	skel->bss->max = max;                          \
	skel->bss->u = ustack;                         \
	skel->bss->k = kstack;                         \
	skel->bss->self_pid = self_pid;                \
	__VA_ARGS__;                                   \
	err = skel->load(skel);                        \
	CHECK_ERR(err, "Fail to load BPF skeleton");   \
	OPEN_ALL_MAP()

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

#include <sys/syscall.h>
#include <unistd.h>
/// @brief staring perf event
/// @param hw_event attribution of the perf event
/// @param pid the pid to track. 0 for the calling process. -1 for all processes.
/// @param cpu the cpu to track. -1 for all cpu
/// @param group_fd fd of event group leader
/// @param flags setting
/// @return fd of perf event
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
							unsigned long flags)
{
	return syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

/// @brief 向指定用户函数附加一个ebpf处理函数
/// @param skel ebpf程序骨架
/// @param sym_name 用户态函数名字面量，不加双引号
/// @param prog_name ebpf处理函数，skel->progs中的成员名
/// @param is_retprobe 布尔类型，是否附加到符号返回处
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe)  \
	do                                                           \
	{                                                            \
		DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,        \
							.retprobe = is_retprobe);            \
		skel->links.prog_name = bpf_program__attach_uprobe_opts( \
			skel->progs.prog_name,                               \
			pid,                                                 \
			object,                                              \
			1,                                                   \
			&uprobe_opts);                                       \
	} while (false)
#else
#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe)  \
	do                                                           \
	{                                                            \
		LIBBPF_OPTS(                                             \
			bpf_uprobe_opts, uprobe_opts,                        \
			.retprobe = is_retprobe,                             \
			.func_name = #sym_name);                             \
		skel->links.prog_name = bpf_program__attach_uprobe_opts( \
			skel->progs.prog_name,                               \
			pid,                                                 \
			object,                                              \
			0,                                                   \
			&uprobe_opts);                                       \
	} while (false)
#endif

/// @brief 检查处理函数是否已经被附加到函数上
/// @param skel ebpf程序骨架
/// @param prog_name ebpf处理函数
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define __CHECK_PROGRAM(skel, prog_name)                                                      \
	do                                                                                        \
	{                                                                                         \
		if (!skel->links.prog_name)                                                           \
		{                                                                                     \
			fprintf(stderr, "[%s] no program attached for" #prog_name "\n", strerror(errno)); \
			return -errno;                                                                    \
		}                                                                                     \
	} while (false)

/// @brief 向指定用户函数附加一个处理函数并检查是否连接成功
/// @param skel ebpf程序骨架
/// @param sym_name 要连接的用户函数
/// @param prog_name ebpf处理函数
/// @param is_retprobe 布尔类型，是否附加到函数返回处
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
	do                                                                  \
	{                                                                   \
		__ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe);        \
		__CHECK_PROGRAM(skel, prog_name);                               \
	} while (false)

/// @brief 向指定用户态函数入口处附加一个处理函数
/// @param skel ebpf程序骨架
/// @param sym_name 要附加的用户态函数名
/// @param prog_name ebpf处理函数
#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)

/// @brief 向指定用户态函数返回处附加一个处理函数
/// @param skel ebpf程序骨架
/// @param sym_name 用户态函数名
/// @param prog_name ebpf处理函数
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

/// @brief 向指定用户态函数入口处附加一个处理函数并检查是否连接成功
/// @param skel ebpf程序骨架
/// @param sym_name 要跟踪的用户态函数名字面量，不带双引号
/// @param prog_name ebpf处理函数，skel->progs中的成员
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)

/// @brief 向指定用户态函数返回处附加一个处理函数并检查是否连接成功
/// @param skel ebpf程序骨架
/// @param sym_name 要附加的用户态函数名，字面量，不带双引号
/// @param prog_name ebpf处理函数，skel->progs中的成员
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

#endif
