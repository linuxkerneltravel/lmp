// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "minimal.skel.h"	//包含了 BPF 字节码和相关的管理函数

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)		//arg即自变量argument
{
	return vfprintf(stderr, format, args);		//将可变参数列表的格式化数据写入流。stderr指向标识输出流的FILE对象的指针。format包含格式字符串的C字符串，其格式与printf中的格式相同。args变量参数列表的值。
}

int main(int argc, char **argv)
{
	struct minimal_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* 设置libbpf错误和调试信息回调 */
	libbpf_set_print(libbpf_print_fn);

	/* 打开BPF应用程序 */
	skel = minimal_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* 确保BPF程序只处理来自进程的write()系统调用 */
	skel->bss->my_pid = getpid();		//bss段通常是指用来存放程序中未初始化的或者初始化为0的全局变量和静态变量的一块内存区域。

	/* 加载并验证BPF程序 */
	err = minimal_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* 附加跟踪点处理程序 */
	err = minimal_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		/* 触发我们的BPF计划 */
		fprintf(stderr, ".");
		sleep(1);
	}

/* 卸载BPF程序 */
cleanup:
	minimal_bpf__destroy(skel);
	return -err;
}
