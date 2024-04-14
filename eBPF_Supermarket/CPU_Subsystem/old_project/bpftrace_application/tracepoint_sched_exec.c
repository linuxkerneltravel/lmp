#!/usr/bin/env bpftrace
#include <linux/sched.h>

tracepoint:sched:sched_process_exec
{
    // 经过验证，创建的进程的pid与当前进程的pid相同，即pid == args->pid
    printf("%d %d\n", args->pid, args->old_pid); // 新旧pid也相同
    @[comm] = count();
}