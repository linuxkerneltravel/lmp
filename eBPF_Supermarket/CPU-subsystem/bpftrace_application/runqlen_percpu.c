#!/usr/bin/env bpftrace

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
        printf("Sampling run queue length... Hit Ctrl-C to end.\n");
}

kprobe:update_rq_clock
{
        $rq = (struct rq *)arg0;
        @q[cpu] = lhist($rq->nr_running, 0, 100, 1);
        
        $task = (struct task_struct *)curtask;
        $my_q = (struct cfs_rq_partial *)$task->se.cfs_rq;
        $len = $my_q->nr_running;
        // $len = $len > 0 ? $len - 1 : 0;
        @runqlen = lhist($len, 0, 100, 1);
}