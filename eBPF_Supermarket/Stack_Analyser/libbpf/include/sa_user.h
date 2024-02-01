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

#include "sa_common.h"

struct diy_header {
	uint64_t len;
	char name[32];
	int magic;
};

/// @brief 栈处理工具当前支持的采集模式
typedef enum {
    MOD_ON_CPU,  // on—cpu模式
    MOD_OFF_CPU, // off-cpu模式
    MOD_MEM,     // 内存模式
    MOD_IO,      // io模式
    MOD_RA,      // 预读取分析模式
	MOD_NUM		// 该枚举类值的总数
} StackCollectMode;

char StackCollectModeName[MOD_NUM][16] = {
	"on_cpu",
	"off_cpu",
	"memory",
	"io",
	"readahead"
};

typedef enum {
    NO_OUTPUT,
    LIST_OUTPUT
} display_t;

typedef enum {
    COUNT,
    SIZE,
    AVE
} io_mod;

/// @brief 获取epbf程序中指定表的文件描述符
/// @param name 表的名字
#define OPEN_MAP(name) bpf_map__fd(skel->maps.name)

/// @brief 获取所有表的文件描述符
#define OPEN_ALL_MAP()                  \
	value_fd = OPEN_MAP(psid_count);    \
	tgid_fd = OPEN_MAP(pid_tgid);       \
	comm_fd = OPEN_MAP(pid_comm);       \
	trace_fd = OPEN_MAP(stack_trace);

/// @brief 加载、初始化参数并打开指定类型的ebpf程序
/// @param ... 一些ebpf程序全局变量初始化语句
/// @note 失败会使上层函数返回-1
#define StackProgLoadOpen(...) \
	skel = skel->open(NULL);                       \
	CHECK_ERR(!skel, "Fail to open BPF skeleton"); \
	skel->bss->min = min;                          \
	skel->bss->max = max;                          \
	skel->bss->u = ustack;						   \
	skel->bss->k = kstack;						   \
	skel->bss->self_pid = self_pid;				   \
	__VA_ARGS__;                                   \
	err = skel->load(skel);                		   \
	CHECK_ERR(err, "Fail to load BPF skeleton");   \
	OPEN_ALL_MAP()

/// @class rapidjson::Value
/// @brief 添加字符串常量键和任意值，值可使用内存分配器
/// @param k 设置为键的字符串常量
/// @param ... 对应值，可使用内存分配器
#define AddStringAndValue(k, ...)                   \
	AddMember(k,                                    \
			  rapidjson::Value(__VA_ARGS__).Move(), \
			  alc)

/// @class rapidjson::Value
/// @brief 添加需要分配内存的变量字符串键和值，值可使用内存分配器
/// @param k 设置为键的字符串变量
/// @param ... 对应值，可使用内存分配器
#define AddKeyAndValue(k, ...)                 	\
	AddMember(									\
		rapidjson::Value(k, alc).Move(),      	\
		rapidjson::Value(__VA_ARGS__).Move(), 	\
		alc                                     \
	)

/// @class rapidjson::Value::kArray
/// @brief 添加字符串变量
/// @param v 要添加的字符串变量
#define PushString(v) PushBack(rapidjson::Value(v, alc), alc)

/// @brief 检查错误，若错误成立则打印带原因的错误信息并使上层函数返回-1
/// @param cond 被检查的条件表达式
/// @param info 要打印的错误信息
#define CHECK_ERR(cond, ...)                         \
    if (cond) {                                      \
        fprintf(stderr, __VA_ARGS__);                \
        fprintf(stderr, " [%s]\n", strerror(errno)); \
        return -1;                                   \
    }

#define CHECK_ERR_VALUE(cond, val, ...)                         \
    if (cond) {                                      \
        fprintf(stderr, __VA_ARGS__);                \
        fprintf(stderr, " [%s]\n", strerror(errno)); \
        return val;                                   \
    }

#include <stdlib.h>
/// @brief 检查错误，若错误成立则打印带原因的错误信息并退出
/// @param cond 被检查的条件表达式
/// @param info 要打印的错误信息
#define CHECK_ERR_EXIT(cond, ...)                    \
    if (cond) {                                      \
        fprintf(stderr, __VA_ARGS__);                \
        fprintf(stderr, " [%s]\n", strerror(errno)); \
        exit(EXIT_FAILURE);                          \
    }

/// @brief 初始化eventfd
/// @param fd 事件描述符
/// @return 成功返回0，失败返回-1
int event_init(int *fd) {
	CHECK_ERR(!fd, "pointer to fd is null");
	const int tmp_fd = eventfd(0, EFD_CLOEXEC & EFD_SEMAPHORE);
	CHECK_ERR(tmp_fd < 0, "failed to create event fd");
	*fd = tmp_fd;
	return 0;
}

/// @brief 等待事件
/// @param fd 事件描述符
/// @param expected_event 期望事件
/// @return 成功返回0，失败返回-1
int event_wait(int fd, uint64_t expected_event) {
	uint64_t event = 0;
	const ssize_t bytes = read(fd, &event, sizeof(event));

	CHECK_ERR(bytes < 0, "failed to read from fd")
	else CHECK_ERR(bytes != sizeof(event), "read unexpected size");

	CHECK_ERR(event != expected_event, "read event %lu, expected %lu", event, expected_event);

	return 0;
}

pid_t fork_sync_exec(const char *command, int fd) {
	// auto cmd = std::string(command) + " > /dev/null";
	const pid_t pid = fork();
	sigset_t ss, oss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigprocmask(SIG_BLOCK, &ss, &oss);
	switch (pid)
	{
	case -1:
		perror("failed to create child process");
		break;
	case 0:
		CHECK_ERR_EXIT(event_wait(fd, (uint64_t)1), "failed to wait on event");
		printf("received go event. executing child command\n");
		CHECK_ERR_EXIT(execl("/bin/bash", "bash", "-c", command, NULL), "failed to execute child command");
		break;
	default:
		printf("child created with pid: %d\n", pid);
		sigprocmask(SIG_SETMASK, &oss, NULL);
		break;
	}
	return pid;
}

/// @brief 更新事件
/// @param fd 事件描述符
/// @param event 通知的事件
/// @return 失败返回-1，成功返回0
int event_notify(int fd, uint64_t event) {
	const ssize_t bytes = write(fd, &event, sizeof(event));
	CHECK_ERR(bytes < 0, "failed to write to fd")
	else CHECK_ERR(bytes != sizeof(event), "attempted to write %zu bytes, wrote %zd bytes", sizeof(event), bytes);
	return 0;
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
							unsigned long flags) {
	return syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

/// @brief 向指定用户函数附加一个ebpf处理函数
/// @param skel ebpf程序骨架
/// @param sym_name 用户态函数名
/// @param prog_name ebpf处理函数
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
    do {                                                         \
        LIBBPF_OPTS(                                             \
            bpf_uprobe_opts, uprobe_opts,                        \
                    .retprobe = is_retprobe,                     \
                    .func_name = #sym_name                       \
        );                                                       \
        skel->links.prog_name = bpf_program__attach_uprobe_opts( \
            skel->progs.prog_name,                               \
            pid,                                                 \
            object,                                              \
            0,                                                   \
            &uprobe_opts                                         \
        );                                                       \
    } while (false)
#endif

/// @brief 检查处理函数是否已经被附加到函数上
/// @param skel ebpf程序骨架
/// @param prog_name ebpf处理函数
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define __CHECK_PROGRAM(skel, prog_name)                                                      \
    do {                                                                                      \
        if (!skel->links.prog_name) {                                                         \
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
    do {                                                                \
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
/// @param sym_name 要跟踪的用户态函数名
/// @param prog_name ebpf处理函数
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)

/// @brief 向指定用户态函数返回处附加一个处理函数并检查是否连接成功
/// @param skel ebpf程序骨架
/// @param sym_name 要附加的用户态函数名
/// @param prog_name ebpf处理函数
/// @note 如果检查到没有被附加则使上层函数返回负的错误代码
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)


#endif