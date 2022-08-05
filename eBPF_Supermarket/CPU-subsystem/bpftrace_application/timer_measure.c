#!/usr/bin/env bpftrace

#include <linux/sched.h>

BEGIN {
    printf("START!\n");
    @start = nsecs;
}

kprobe:hrtimer_interrupt {
    @ = count();
    if (nsecs - @start > (1 * 1000000000)) {
        exit();
    }
}