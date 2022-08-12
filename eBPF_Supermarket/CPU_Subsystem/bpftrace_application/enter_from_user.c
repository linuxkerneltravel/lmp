#!/usr/bin/env bpftrace

#include <linux/sched.h>

kprobe:exit_to_user_mode_prepare
{
    @ = count();
}