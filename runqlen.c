#include <linux/sched.h>

struct cfs_rq_partial {
	struct load_weight load;
	unsigned int nr_running;
	unsigned int h_nr_running;
	unsigned int idle_h_nr_running;
}; // fetched from vmlinux.h 5.13

profile:hz:99
{
	$task = (struct task_struct *)curtask;
	$my_q = (struct cfs_rq_partial *)$task->se.cfs_rq;
	$len = $my_q->nr_running;
	$len = $len > 0 ? $len - 1 : 0;	// subtract currently running task
	@runqlen = lhist($len, 0, 100, 1);
}

tracepoint:sched:sched_switch
{
        if (args->prev_state == TASK_RUNNING) {
                @qtime[args->prev_pid] = nsecs;
        }

        $ns = @qtime[args->next_pid];
        if ($ns) {
                @usecs = hist((nsecs - $ns) / 1000);
        }
        delete(@qtime[args->next_pid]);
}



#!/usr/bin/env bpftrace
/*
 * runqlen.bt	CPU scheduler run queue length as a histogram.
 *		For Linux, uses bpftrace, eBPF.
 *
 * This is a bpftrace version of the bcc tool of the same name.
 *
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 07-Oct-2018	Brendan Gregg	Created this.
 */



// Until BTF is available, we'll need to declare some of this struct manually,
// since it isn't available to be #included. This will need maintenance to match
// your kernel version. It is from kernel/sched/sched.h:
/*
struct cfs_rq_partial {
	struct load_weight load;
	unsigned long runnable_weight;
	unsigned int nr_running;
	unsigned int h_nr_running;
}; // original
*/

BEGIN
{
	printf("Sampling run queue length at 99 Hertz... Hit Ctrl-C to end.\n");
}
