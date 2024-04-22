#!/usr/bin/env bpftrace
#include <linux/sched.h>

tracepoint:sched:sched_switch
{
    if (args->prev_pid != args->next_pid) {
        @wait_begin_time[args->prev_pid] = nsecs;
        if (@wait_begin_time[args->next_pid] != 0) {
            @wait_time[args->next_pid] += (nsecs - @wait_begin_time[args->next_pid]);
        }
    }
}

tracepoint:raw_syscalls:sys_enter
{
    @wait_time[pid] = 0;
    @sys_enter_time[pid] = nsecs;
}

tracepoint:raw_syscalls:sys_exit
{
    $T_enter = @sys_enter_time[pid];
    if ($T_enter) {
        $duration = nsecs - $T_enter - @wait_time[pid];
        @wait_time[pid] = 0;
        if ($duration > 1000000000) {
            printf("%d\n", $duration);
        }
        @syscall_duration = hist(($duration) / 1000);
    }
    delete(@sys_enter_time[pid]);
}

END
{
    clear(@sys_enter_time);
    clear(@wait_time);
    clear(@wait_begin_time);
}