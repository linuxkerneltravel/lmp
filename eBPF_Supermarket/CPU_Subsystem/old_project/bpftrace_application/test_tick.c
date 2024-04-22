#!/usr/bin/env bpftrace

#include <linux/sched.h>

BEGIN
{
        printf("Sampling run queue length... Hit Ctrl-C to end.\n");
}

kprobe:account_idle_ticks
{
        $ticks = arg0;
        @q[*$ticks] += 1;
}