#!/usr/bin/env bpftrace

#include <linux/sched.h>

/*从此开始是CFS的队列*/
struct cfs_rq {
	struct load_weight load;
	unsigned int nr_running;
	unsigned int h_nr_running;
	unsigned int idle_h_nr_running;
};
/*结束*/


/*从此开始是实时调度器的队列*/
// struct list_head {
// 	struct list_head *next;
// 	struct list_head *prev;
// };

struct rt_prio_array {
	long unsigned int bitmap[2];
	struct list_head queue[100];
};

struct rt_rq {
	struct rt_prio_array active;
	unsigned int rt_nr_running;
	unsigned int rr_nr_running;
};
/*到此结束*/

/*dl scheduling 的结构体*/
// struct rb_node {
// 	long unsigned int __rb_parent_color;
// 	struct rb_node *rb_right;
// 	struct rb_node *rb_left;
// };

// struct rb_root {
// 	struct rb_node *rb_node;
// };

// struct rb_root_cached {
// 	struct rb_root rb_root;
// 	struct rb_node *rb_leftmost;
// };

struct dl_rq {
	struct rb_root_cached root;
	long unsigned int dl_nr_running;
};
/*结束*/


struct uclamp_bucket {
	long unsigned int value: 11;
	long unsigned int tasks: 53;
};

struct uclamp_rq {
	unsigned int value;
	struct uclamp_bucket bucket[5];
};

struct rq_partial {
	raw_spinlock_t lock;
	unsigned int nr_running;
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
	unsigned int numa_migrate_on;
	long unsigned int last_blocked_load_update_tick;
	unsigned int has_blocked_load;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	call_single_data_t nohz_csd;
	unsigned int nohz_tick_stopped;
	atomic_t nohz_flags;
	unsigned int ttwu_pending;
	u64 nr_switches;
	long: 64;
	struct uclamp_rq uclamp[2];
	unsigned int uclamp_flags;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	struct cfs_rq cfs;
	struct rt_rq rt;
	struct dl_rq dl;
};

// 注意：结构体定义需要放在BEGIN前面
BEGIN {
    printf("starting collecting se data...");
}

// 分别计算和保存各参数的最大值、最小值、平均值以及分布等等
kprobe:update_rq_clock {
    $rq = (struct rq_partial *)arg0;
    $len = $rq->cfs.nr_running;
    @cfs_hist[cpu] = lhist($len, 0, 100, 1);
	$dl = ($rq->dl);
	// @rt_hist = lhist($rq->rt.rt_nr_running + $rq->rt.rr_nr_running, 0, 200, 1); // 使用@型的变量可以保存数据
	// printf("rt_nr_running = %lu, rr_nr_running = %lu\n", $rq->rt.rt_nr_running, $rq->rt.rr_nr_running);
	@dl_hist = lhist($rq->dl.dl_nr_running, 0, 100, 1);
	printf("dl_nr_running = %lu\n", $dl.dl_nr_running);
}

