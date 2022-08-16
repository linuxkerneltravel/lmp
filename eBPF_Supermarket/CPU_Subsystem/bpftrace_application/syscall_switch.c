#!/usr/bin/env bpftrace
#include <linux/sched.h>

tracepoint:sched:sched_switch
{
    if (args->prev_pid != args->next_pid) {
        // @last_run[args->next_pid] = nsecs;
        if (@last_run[args->prev_pid] != 0) {
            @run_time[args->prev_pid] += (nsecs - @last_run[args->prev_pid]);
        }
    }
    @sched_count += 1;
}

tracepoint:raw_syscalls:sys_enter
{
    @run_time[pid] = 0;
    @enter_count[pid] = @sched_count;
    @sys_enter_time[pid] = nsecs;
    @last_run[pid] = nsecs;
}

tracepoint:raw_syscalls:sys_exit
{
    $T_enter = @sys_enter_time[pid];
    if ($T_enter) {
        $time_elapsed = nsecs - $T_enter;
        $duration = nsecs - @last_run[pid];
        if ($duration > $time_elapsed) {
            printf("duration = %d, time_elasped = %d\n", $duration, $time_elapsed);
        }

        @syscall_duration = hist(($duration) / 1000);
        @enter_last_count = hist(@sched_count - @enter_count[pid]);
    }
    delete(@sys_enter_time[pid]);
}

END
{
    clear(@sys_enter_time);
}