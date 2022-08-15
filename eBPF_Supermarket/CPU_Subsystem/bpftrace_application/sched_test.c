#!/usr/bin/env bpftrace

#include <linux/sched.h>

tracepoint:sched:sched_switch {
    printf("next_pid = %6d;  prev_pid = %6d;  prev_state = %04x; %d\n", 
        args->next_pid, args->prev_pid, curtask->state, cpu);
}