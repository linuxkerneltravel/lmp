#!/usr/bin/env bpftrace
#include <linux/sched.h>

tracepoint:syscalls:sys_enter_execve
{
    // 经过验证，创建的进程的pid与当前进程的pid相同，即pid == args->pid
    printf("%s\n", str(args->filename));
}