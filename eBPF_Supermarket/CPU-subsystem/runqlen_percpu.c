#!/usr/bin/env bpftrace
/*
 * runqlen.bt   CPU scheduler run queue length as a histogram.
 *              For Linux, uses bpftrace, eBPF.
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 07-Oct-2018  Brendan Gregg   Created this.
 */

#include <linux/sched.h>

struct atomic_t {
        int counter;
};

// struct qspinlock {
// 	union {
// 		atomic_t val;
// 		struct {
// 			u8 locked;
// 			u8 pending;
// 		};
// 		struct {
// 			u16 locked_pending;
// 			u16 tail;
// 		};
// 	};
// };

// struct raw_spinlock {
// 	struct qspinlock raw_lock;
// };

struct rq {
	struct raw_spinlock lock;
	unsigned int nr_running;
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
	unsigned int numa_migrate_on;
	long unsigned int last_blocked_load_update_tick;
	unsigned int has_blocked_load;
}


// Until BTF is available, we'll need to declare some of this struct manually,
// since it isn't available to be #included. This will need maintenance to match
// your kernel version. It is from kernel/sched/sched.h:
struct cfs_rq_partial {
        struct load_weight load;
        unsigned long runnable_weight;
        unsigned int nr_running;
        unsigned int h_nr_running;
};

BEGIN
{
        printf("Sampling run queue length at 99 Hertz... Hit Ctrl-C to end.\n");
}

// 逐CPU显示运行队列长度
// 运行队列长度是指为RUNNABLE的进程的数目，与负载略有不同
kprobe:update_rq_clock
{
        $task = (struct task_struct *)curtask;
        $cpu = $task->on_cpu;
        $rq = (struct rq *)arg0;
        @q[cpu] = lhist($rq->nr_running, 0, 100, 1);
        // printf("now = %d\n", nsecs);
}