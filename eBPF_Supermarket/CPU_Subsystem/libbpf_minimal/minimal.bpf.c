// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>			//包括一些与BPF相关的基本类型和常量
#include <bpf/bpf_helpers.h>	//包含了BPF 辅助函数

char LICENSE[] SEC("license") = "Dual BSD/GPL";		//LICENSE变量定义BPF代码的许可证。SEC()（由提供bpf_helpers.h）指定节，并将变量和函数放入指定的部分。

int my_pid = 0;		//将从下面的用户空间代码中使用进程的实际PID进行初始化

//定义将被加载到内核中的BPF程序。每次write()从任何用户空间应用程序调用syscall时都会调用该程序。
SEC("tp/syscalls/sys_enter_write")			//tp是tracepoint的意思，SEC是section的意思
int handle_tp(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	bpf_printk("BPF triggered from PID %d.\n", pid);

	return 0;
}
